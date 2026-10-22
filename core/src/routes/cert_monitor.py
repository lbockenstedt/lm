"""Cert Expiry Monitor routes — GLOBAL ADMIN ONLY (on top of the /api/* session
gate). Config lives in global_config["cert_monitor"]; results are written to
$LM_STATE_DIR/cert_monitor.json by cert_monitor.run_checks. A startup-launched
scheduler runs a check at most once per 24h while the feature is enabled, and
evaluates the alert rules (cert_monitor_alerts) after every check and tick."""
import asyncio
import datetime as _dt
import logging

import cert_monitor as cm
import cert_monitor_alerts as cma
from api import HTTPException, Request

logger = logging.getLogger("Hub")

SCHEDULER_TICK_S = 900


def register(app, hub, ctx):
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    run_lock = asyncio.Lock()
    alert_lock = asyncio.Lock()
    runtime = {"running": False, "task": None, "scheduler": None}

    def _guard(request: Request):
        sess = _session_user(request)
        if not (sess and _is_admin(sess)):
            raise HTTPException(status_code=403, detail="Admin only")
        return sess

    def _cfg():
        gc = hub.state.system_state.get("global_config", {}) or {}
        return cm.normalize_config(gc.get("cert_monitor"))

    async def _save_cfg(cfg):
        gc = hub.state.system_state.setdefault("global_config", {})
        gc["cert_monitor"] = cfg
        hub.state._mark_dirty()
        saver = getattr(hub.state, "save_state_now", None)
        if saver:
            try:
                await saver()
            except Exception as e:  # noqa: BLE001
                logger.warning("[certmon] state save failed: %s", e)

    async def _run(reason):
        if run_lock.locked():
            return False
        async with run_lock:
            runtime["running"] = True
            try:
                hosts = cm.effective_hosts(_cfg())
                logger.info("[certmon] checking %d host(s) (%s)", len(hosts), reason)
                data = await asyncio.to_thread(cm.run_checks, hosts)
                data["trigger"] = reason
                await asyncio.to_thread(cm.save_results, data)
                c = data["counts"]
                logger.info("[certmon] done in %ss: red=%d yellow=%d green=%d error=%d",
                            data["duration_s"], c.get("red", 0), c.get("yellow", 0),
                            c.get("green", 0), c.get("error", 0))
                await _evaluate_alerts(data)
            except Exception as e:  # noqa: BLE001
                logger.warning("[certmon] check failed: %s", e)
            finally:
                runtime["running"] = False
        return True

    def _kick(reason):
        if run_lock.locked():
            return False
        runtime["task"] = asyncio.create_task(_run(reason))
        return True

    def _refresh_days(results, now):
        """Recompute days_left / status from not_after so the view stays
        accurate between the once-a-day checks."""
        out = []
        for r in results or []:
            r = dict(r)
            na = r.get("not_after")
            if na:
                try:
                    ts = _dt.datetime.fromisoformat(na)
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=_dt.timezone.utc)
                    r["days_left"] = int((ts - now).total_seconds() // 86400)
                    r["status"] = cm.classify(r["days_left"])
                except ValueError:
                    pass
            out.append(r)
        return cm.sort_results(out)

    async def _evaluate_alerts(data=None):
        if not _cfg()["enabled"]:
            return {}
        async with alert_lock:
            try:
                if data is None:
                    data = await asyncio.to_thread(cm.load_results)
                if not data.get("last_run"):
                    return {}
                results = _refresh_days(data.get("results"),
                                        _dt.datetime.now(_dt.timezone.utc))
                return await cma.run_alerts(hub, results)
            except Exception as e:  # noqa: BLE001
                logger.warning("[certmon] alert evaluation failed: %s", e)
                return {}

    @app.get("/api/certmon/status")
    async def certmon_status(request: Request):
        """Lightweight flag for the left-nav: is the feature enabled?"""
        _guard(request)
        return {"enabled": _cfg()["enabled"], "running": runtime["running"]}

    @app.get("/api/certmon/overview")
    async def certmon_overview(request: Request):
        _guard(request)
        cfg = _cfg()
        data = await asyncio.to_thread(cm.load_results)
        now = _dt.datetime.now(_dt.timezone.utc)
        results = _refresh_days(data.get("results"), now)
        counts = {s: 0 for s in ("red", "yellow", "green", "error", "unknown")}
        for r in results:
            counts[r.get("status", "unknown")] = counts.get(r.get("status", "unknown"), 0) + 1
        next_run = None
        if cfg["enabled"] and data.get("last_run"):
            try:
                next_run = (_dt.datetime.fromisoformat(data["last_run"])
                            + _dt.timedelta(seconds=cm.CHECK_INTERVAL_S)).isoformat()
            except ValueError:
                next_run = None
        return {
            "config": cfg,
            "builtin_hosts": cm.BUILTIN_HOSTS,
            "thresholds": {"red_days": cm.RED_DAYS, "yellow_days": cm.YELLOW_DAYS},
            "running": runtime["running"],
            "last_run": data.get("last_run"),
            "next_run": next_run,
            "duration_s": data.get("duration_s"),
            "counts": counts,
            "results": results,
            "results_file": cm.results_path(),
        }

    @app.put("/api/certmon/config")
    async def certmon_config(request: Request):
        _guard(request)
        body = await request.json()
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="JSON object expected")
        cur = _cfg()
        if "custom_hosts" in body:
            raw = body["custom_hosts"]
            if isinstance(raw, str):
                raw = [x for x in raw.replace(",", "\n").splitlines()]
            if not isinstance(raw, list):
                raise HTTPException(status_code=400, detail="custom_hosts must be a list")
            bad = [x for x in raw if str(x).strip() and not cm.parse_host_entry(x)]
            if bad:
                raise HTTPException(status_code=400,
                                    detail=f"Invalid host(s): {', '.join(map(str, bad[:5]))}")
            cur["custom_hosts"] = raw
        if "disabled_builtin" in body:
            if not isinstance(body["disabled_builtin"], list):
                raise HTTPException(status_code=400, detail="disabled_builtin must be a list")
            cur["disabled_builtin"] = body["disabled_builtin"]
        was_enabled = cur["enabled"]
        if "enabled" in body:
            cur["enabled"] = body["enabled"] is True or str(body["enabled"]).lower() in ("true", "1", "on", "yes")
        cfg = cm.normalize_config(cur)
        await _save_cfg(cfg)
        started = False
        if cfg["enabled"] and not was_enabled:
            data = await asyncio.to_thread(cm.load_results)
            if cm.is_due(data):
                started = _kick("enabled")
        return {"status": "ok", "config": cfg, "check_started": started}

    @app.post("/api/certmon/run")
    async def certmon_run(request: Request):
        _guard(request)
        if not _cfg()["enabled"]:
            raise HTTPException(status_code=409, detail="Cert Expiry Monitor is disabled")
        started = _kick("manual")
        return {"status": "started" if started else "already_running"}

    # ── alert rules (breach + recovery digests; see cert_monitor_alerts) ──
    @app.get("/api/certmon/alerts/rules")
    async def certmon_alert_rules(request: Request):
        _guard(request)
        return {"rules": cma.get_rules(hub), "triggers": list(cma.TRIGGERS),
                "trigger_labels": cma.TRIGGER_LABELS, "services": cma.service_names(),
                "default_threshold_days": cma.DEFAULT_THRESHOLD_DAYS}

    async def _body(request):
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = None
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="JSON object expected")
        return body

    @app.post("/api/certmon/alerts/rules")
    async def certmon_alert_rule_create(request: Request):
        _guard(request)
        body = await _body(request)
        rules = cma.get_rules(hub)
        if len(rules) >= cma.MAX_RULES:
            raise HTTPException(status_code=400, detail=f"At most {cma.MAX_RULES} rules")
        rule = cma.clean_rule(body)
        rules.append(rule)
        await cma.save_rules(hub, rules)
        if rule["enabled"]:
            asyncio.create_task(_evaluate_alerts())
        return {"saved": True, "rule": rule}

    @app.put("/api/certmon/alerts/rules/{rid}")
    async def certmon_alert_rule_update(rid: str, request: Request):
        _guard(request)
        body = await _body(request)
        rules = cma.get_rules(hub)
        for i, r in enumerate(rules):
            if r.get("id") == rid:
                rules[i] = cma.clean_rule(body, r)
                await cma.save_rules(hub, rules)
                if rules[i]["trigger"] != r.get("trigger"):
                    async with alert_lock:
                        await asyncio.to_thread(cma.reset_rule_state, rid)
                if rules[i]["enabled"]:
                    asyncio.create_task(_evaluate_alerts())
                return {"saved": True, "rule": rules[i]}
        raise HTTPException(status_code=404, detail="Rule not found")

    @app.delete("/api/certmon/alerts/rules/{rid}")
    async def certmon_alert_rule_delete(rid: str, request: Request):
        _guard(request)
        rules = cma.get_rules(hub)
        keep = [r for r in rules if r.get("id") != rid]
        removed = len(keep) != len(rules)
        if removed:
            await cma.save_rules(hub, keep)
        return {"removed": removed}

    @app.post("/api/certmon/alerts/rules/{rid}/test")
    async def certmon_alert_rule_test(rid: str, request: Request):
        _guard(request)
        rule = next((r for r in cma.get_rules(hub) if r.get("id") == rid), None)
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
        if not rule.get("recipients"):
            raise HTTPException(status_code=400, detail="This rule has no recipients")
        data = await asyncio.to_thread(cm.load_results)
        results = _refresh_days(data.get("results"), _dt.datetime.now(_dt.timezone.utc))
        if not await cma.send_test(hub, rule, results):
            raise HTTPException(status_code=400, detail="Send failed — check Setup → Notifications")
        return {"sent": True, "to": rule["recipients"]}

    async def _scheduler():
        await asyncio.sleep(60)
        while True:
            try:
                if _cfg()["enabled"]:
                    data = await asyncio.to_thread(cm.load_results)
                    if cm.is_due(data):
                        await _run("daily")
                    else:
                        await _evaluate_alerts(data)
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                logger.warning("[certmon] scheduler tick failed: %s", e)
            await asyncio.sleep(SCHEDULER_TICK_S)

    async def _start_scheduler():
        try:
            if runtime["scheduler"] is None:
                runtime["scheduler"] = asyncio.create_task(_scheduler())
        except Exception as e:  # noqa: BLE001
            logger.warning("[certmon] scheduler start failed: %s", e)

    async def _stop_scheduler():
        t = runtime.get("scheduler")
        if t:
            t.cancel()

    app.router.on_startup.append(_start_scheduler)
    app.router.on_shutdown.append(_stop_scheduler)
