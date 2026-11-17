"""Cert Expiry Monitor routes — GLOBAL ADMIN ONLY (on top of the /api/* session
gate). Config lives in global_config["cert_monitor"]; results are written to
$LM_STATE_DIR/cert_monitor.json by cert_monitor.run_checks. A startup-launched
scheduler runs a check once per 24h (hourly while a cert expires within a
day) while the feature is enabled, and
evaluates the alert rules (cert_monitor_alerts) after every check and tick.
Per-cert ignores (global_config["cert_monitor_ignored"], keyed host:port) keep
a cert listed but drop it from the counts and the alert evaluation.
Before a check, the built-in Mist / Central host list is refreshed from the
vendor pages once a day (cert_monitor.refresh_sources).

LE deployment verification: every Let's Encrypt cert the hub has pushed to a
target is auto-added (from the hub's le_cache) and its served cert compared
with the issued one. These LE endpoints are checked even while the monitor is
disabled (an "le"-scope run), so a cert that never reached its host can't go
unnoticed; a new cert or push state triggers a check on the next tick."""
# Locks, background tasks and thread offloading for the blocking checks.
import asyncio
# Current time and expiry-date maths.
import datetime as _dt
# Logging under the shared "Hub" logger.
import logging

# Tenant scoping helpers.
import access
# Cert check engine (config, host lists, TLS checks, results file) and its alert rules.
import cert_monitor as cm
import cert_monitor_alerts as cma
# Shared Hub helpers: HTTP error type and request object.
from api import HTTPException, Request

logger = logging.getLogger("Hub")

# How often (seconds) the scheduler wakes to see if a check or alert run is due (15 min).
SCHEDULER_TICK_S = 900


def register(app, hub, ctx):
    """Register the Cert Expiry Monitor routes and its background scheduler."""
    # Session and admin-check helpers from the shared route context.
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    # One check and one alert evaluation at a time; runtime holds the running flag and tasks.
    run_lock = asyncio.Lock()
    alert_lock = asyncio.Lock()
    runtime = {"running": False, "task": None, "scheduler": None}

    def _guard(request: Request):
        """Return the session user, or raise 403 if they are not an admin."""
        sess = _session_user(request)
        if not (sess and _is_admin(sess)):
            raise HTTPException(status_code=403, detail="Admin only")
        return sess

    def _cfg():
        """Return the normalised cert-monitor config from global_config."""
        gc = hub.state.system_state.get("global_config", {}) or {}
        return cm.normalize_config(gc.get("cert_monitor"))

    async def _save_cfg(cfg):
        """Store ``cfg`` as the cert-monitor config and save state now (best effort)."""
        gc = hub.state.system_state.setdefault("global_config", {})
        gc["cert_monitor"] = cfg
        hub.state._mark_dirty()
        # Save straight away if the state supports it; a failure is only logged.
        saver = getattr(hub.state, "save_state_now", None)
        if saver:
            try:
                await saver()
            except Exception as e:  # noqa: BLE001
                logger.warning("[certmon] state save failed: %s", e)

    def _le_entries():
        """Host entries for the LE certs the hub has pushed (from the le cache),
        or None when the cert list can't be read. None is not "no certs": the
        last LE rows are then held (keep_le_results), never cleared."""
        try:
            getter = getattr(hub, "le_cache_get", None)
            certs = cm.le_cert_holder(getter("certs") if getter else None)
            if certs is None:
                return None
            return cm.le_hosts([c for c in certs if isinstance(c, dict)], _target_names())
        except Exception as e:  # noqa: BLE001
            logger.warning("[cert-verify] could not read the LE cert list: %s", e)
            return None

    def _target_names():
        """Spoke and agent ids → display names, for the LE target labels."""
        names = dict(hub.state.system_state.get("module_names", {}) or {})
        # An agent is known by its key and its raw agent_id; show its hostname.
        for pk, info in (getattr(hub, "agent_info", None) or {}).items():
            host = (info or {}).get("hostname") or (info or {}).get("agent_id")
            if host:
                names.setdefault(pk, host)
                names.setdefault((info or {}).get("agent_id") or pk, host)
        return names

    def _due_reason(data, le):
        """Why a check is due now (None if not): the schedule, a full check owed
        after LE-only runs while the monitor was off, an LE change, or the
        hourly re-check of a failing LE endpoint. ``le`` None (the cert list
        is unreadable) is never an LE change and leaves nothing to re-check."""
        enabled = _cfg()["enabled"]
        # The LE set changed since the last run (including to empty, so rows
        # for certs no longer pushed are cleared). Old results have no
        # fingerprint: treat them as checked with no LE certs.
        le_changed = (le is not None and
                      data.get("le_fingerprint", cm.le_fingerprint([])) != cm.le_fingerprint(le))
        # Nothing to check while off with no LE certs.
        if not enabled and not le and not le_changed:
            return None
        # Owed a full check after LE-only runs.
        if enabled and data.get("scope") == "le":
            return "enabled"
        if cm.is_due(data, ignored=_ignored()):
            return "scheduled"
        # A new LE cert or push state: verify it promptly.
        if le_changed:
            return "le-change"
        if le and cm.le_retry_due(data, ignored=_ignored()):
            return "le-retry"
        return None

    def _ignored():
        """Return the normalised per-cert ignore list (keyed host:port)."""
        gc = hub.state.system_state.get("global_config", {}) or {}
        return cm.normalize_ignored(gc.get(cm.IGNORE_KEY))

    async def _save_ignored(ignored):
        """Store the ignore list and save state now (best effort)."""
        gc = hub.state.system_state.setdefault("global_config", {})
        gc[cm.IGNORE_KEY] = ignored
        hub.state._mark_dirty()
        # Save straight away if the state supports it; a failure is only logged.
        saver = getattr(hub.state, "save_state_now", None)
        if saver:
            try:
                await saver()
            except Exception as e:  # noqa: BLE001
                logger.warning("[certmon] ignore-list save failed: %s", e)

    def _view(results, now):
        """Stored results → refreshed days/status, ignore flags applied."""
        return cm.apply_ignored(_refresh_days(results, now), _ignored())

    async def _run(reason):
        """Run one cert check (``reason`` is logged); False if one is already running.
        An LE change or retry while the monitor is enabled probes only the LE
        endpoints and folds them into the last full results, so a failing LE
        endpoint never turns the whole scan hourly."""
        # Skip if a check is already in progress.
        if run_lock.locked():
            return False
        async with run_lock:
            runtime["running"] = True
            # Refresh the built-in vendor host lists first if they're due (failure only logged).
            try:
                try:
                    if cm.sources_due(await asyncio.to_thread(cm.load_sources)):
                        await asyncio.to_thread(cm.refresh_sources)
                except Exception as e:  # noqa: BLE001
                    logger.warning("[certmon] host list refresh failed: %s", e)
                # Hosts: built-in + custom while enabled, plus the pushed LE certs always.
                enabled = _cfg()["enabled"]
                le = _le_entries()
                # Unreadable LE cert list: only the full scan can run, and the
                # last LE results are held.
                held = le is None
                if held and not enabled:
                    logger.warning("[cert-verify] LE cert list unreadable; LE check skipped")
                    return True
                hosts = cm.merge_le_hosts(cm.effective_hosts(_cfg()) if enabled else [], le or [])
                prev = await asyncio.to_thread(cm.load_results)
                le_only = (not held and enabled and reason in ("le-change", "le-retry")
                           and prev.get("scope") == "all")
                if le_only:
                    hosts = [h for h in hosts if h.get("le")]
                # Check every host in a thread, then save the results with the trigger reason.
                logger.info("[certmon] checking %d host(s) (%s, %s LE)", len(hosts), reason,
                            "unreadable" if held else len(le))
                data = await asyncio.to_thread(cm.run_checks, hosts)
                if le_only:
                    # The run's own reason is recorded; the schedule still keys off last_run.
                    data = {**cm.merge_le_results(prev, data), "trigger": reason,
                            "le_fingerprint": cm.le_fingerprint(le)}
                elif held:
                    data = {**cm.keep_le_results(prev, data), "trigger": reason, "scope": "all"}
                else:
                    data.update({"trigger": reason, "scope": "all" if enabled else "le",
                                 "le_checked_at": data["last_run"], "le_fingerprint": cm.le_fingerprint(le)})
                await asyncio.to_thread(cm.save_results, data)
                cm.log_deploy_problems(cm.apply_ignored(data["results"], _ignored()))
                # Log the counts (ignored certs left out), then evaluate the alert rules.
                c = cm.count_statuses(cm.apply_ignored(data["results"], _ignored()))
                logger.info("[certmon] done in %ss: red=%d yellow=%d green=%d error=%d ignored=%d",
                            data["duration_s"], c.get("red", 0), c.get("yellow", 0),
                            c.get("green", 0), c.get("error", 0), c.get("ignored", 0))
                await _evaluate_alerts(data)
            # Any failure is logged; always clear the running flag.
            except Exception as e:  # noqa: BLE001
                logger.warning("[certmon] check failed: %s", e)
            finally:
                runtime["running"] = False
        return True

    def _kick(reason):
        """Start a check in the background; return False if one is already running."""
        if run_lock.locked():
            return False
        runtime["task"] = asyncio.create_task(_run(reason))
        return True

    def _refresh_days(results, now):
        """Recompute days_left / status from not_after so the view stays
        accurate between the scheduled checks."""
        out = []
        # Work on copies; recompute days left and status from the not_after date.
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
                    cm.apply_deploy_status(r)
                except ValueError:
                    pass
            out.append(r)
        # Return them in the standard order.
        return cm.sort_results(out)

    async def _evaluate_alerts(data=None):
        """Evaluate the alert rules against the latest results; return their outcome (or {})."""
        # Nothing to do while the feature is off.
        if not _cfg()["enabled"]:
            return {}
        # Load results if not given; skip if no check has ever run; failures are logged.
        async with alert_lock:
            try:
                if data is None:
                    data = await asyncio.to_thread(cm.load_results)
                if not data.get("last_run"):
                    return {}
                results = _view(data.get("results"), _dt.datetime.now(_dt.timezone.utc))
                # Global rules see only shared-tenant LE certs; a tenant's own
                # LE verdicts alert through its cert_deploy_failed rule instead.
                return await cma.run_alerts(hub, cm.active_results(cm.scope_le_rows(results)))
            except Exception as e:  # noqa: BLE001
                logger.warning("[certmon] alert evaluation failed: %s", e)
                return {}

    def _host_sources():
        """Return a status summary of each built-in vendor host-list source."""
        data = cm.load_sources()
        out = []
        for src in cm.SOURCES:
            d = data.get(src["id"]) or {}
            out.append({"id": src["id"], "service": src["service"], "role": src["role"],
                        "url": src["url"], "hosts": len(d.get("hosts") or []),
                        "updated_at": d.get("updated_at"), "checked_at": d.get("checked_at"),
                        "error": d.get("error") or "", "added": d.get("added") or [],
                        "removed": d.get("removed") or [],
                        "changed_at": d.get("changed_at")})
        return out

    # Left-nav flag: is the monitor enabled/running?
    @app.get("/api/certmon/status")
    async def certmon_status(request: Request):
        """Lightweight flag for the left-nav: is the feature enabled?"""
        _guard(request)
        return {"enabled": _cfg()["enabled"], "running": runtime["running"]}

    # Everything the Cert Expiry Monitor page shows.
    @app.get("/api/certmon/overview")
    async def certmon_overview(request: Request):
        """Return config, host lists, thresholds, run times, counts, results and
        ignores. LE rows are limited to the tenant in view (``?tenant=``,
        resolved by access.request_effective_tenant like other scoped routes)."""
        sess = _guard(request)
        cfg = _cfg()
        # Load stored results and refresh their days left / ignore flags.
        data = await asyncio.to_thread(cm.load_results)
        now = _dt.datetime.now(_dt.timezone.utc)
        results = cm.scope_le_rows(_view(data.get("results"), now),
                                   access.request_effective_tenant(sess, request))
        counts = cm.count_statuses(results)
        # Work out the next scheduled check from the last run (only while enabled).
        next_run = None
        if cfg["enabled"] and data.get("last_run"):
            try:
                next_run = (_dt.datetime.fromisoformat(data["last_run"])
                            + _dt.timedelta(seconds=cm.check_interval(data, _ignored(), now))).isoformat()
            except ValueError:
                next_run = None
        # Return the full page payload.
        return {
            "config": cfg,
            "builtin_hosts": await asyncio.to_thread(cm.builtin_hosts),
            "host_sources": await asyncio.to_thread(_host_sources),
            "thresholds": {"red_days": cm.RED_DAYS, "yellow_days": cm.YELLOW_DAYS},
            "running": runtime["running"],
            "last_run": data.get("last_run"),
            "next_run": next_run,
            "duration_s": data.get("duration_s"),
            "counts": counts,
            "results": results,
            "results_file": cm.results_path(),
            "ignored": _ignored(),
        }

    # Save the cert-monitor config.
    @app.put("/api/certmon/config")
    async def certmon_config(request: Request):
        """Update hosts / disabled / deprecated lists and the enabled flag; maybe start a check."""
        # Admins only; the body must be a JSON object.
        _guard(request)
        body = await request.json()
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="JSON object expected")
        cur = _cfg()
        # Custom hosts: accept a list or a comma/newline string; reject invalid entries.
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
        # Disabled built-in hosts must be a list.
        if "disabled_builtin" in body:
            if not isinstance(body["disabled_builtin"], list):
                raise HTTPException(status_code=400, detail="disabled_builtin must be a list")
            cur["disabled_builtin"] = body["disabled_builtin"]
        # Deprecated hosts must be a list.
        if "deprecated_hosts" in body:
            if not isinstance(body["deprecated_hosts"], list):
                raise HTTPException(status_code=400, detail="deprecated_hosts must be a list")
            cur["deprecated_hosts"] = body["deprecated_hosts"]
        # Accept common truthy spellings for enabled.
        was_enabled = cur["enabled"]
        if "enabled" in body:
            cur["enabled"] = body["enabled"] is True or str(body["enabled"]).lower() in ("true", "1", "on", "yes")
        # Normalise and save.
        cfg = cm.normalize_config(cur)
        await _save_cfg(cfg)
        # Just switched on: start a check now if one is due.
        started = False
        if cfg["enabled"] and not was_enabled:
            data = await asyncio.to_thread(cm.load_results)
            if _due_reason(data, _le_entries()):
                started = _kick("enabled")
        return {"status": "ok", "config": cfg, "check_started": started}

    # Start a manual check now.
    @app.post("/api/certmon/run")
    async def certmon_run(request: Request):
        """Start a check now (409 if the monitor is disabled)."""
        _guard(request)
        if not _cfg()["enabled"]:
            raise HTTPException(status_code=409, detail="Cert Expiry Monitor is disabled")
        started = _kick("manual")
        return {"status": "started" if started else "already_running"}

    # Set or clear the ignore flag on one cert.
    @app.post("/api/certmon/ignore")
    async def certmon_ignore(request: Request):
        """Set / clear the per-cert ignore flag: ``{host, port?, ignored}``
        (``host`` may also be ``host:port``). Ignored certs stay listed but are
        excluded from the status counts and every alert rule."""
        # Admins only; build "host:port" from the body and validate it.
        sess = _guard(request)
        body = await _body(request)
        raw = str(body.get("host") or "").strip()
        if body.get("port") not in (None, "") and ":" not in raw:
            raw = f"{raw}:{body.get('port')}"
        parsed = cm.parse_host_entry(raw)
        if not parsed:
            raise HTTPException(status_code=400, detail="Valid host (and port) required")
        # Key for the cert, and whether to ignore (true) or un-ignore it.
        key = cm.cert_key({"host": parsed[0], "port": parsed[1]})
        want = body.get("ignored", True)
        want = want is True or str(want).lower() in ("true", "1", "on", "yes")
        ignored = _ignored()
        # Ignoring: the host must be monitored (or already ignored) and under the limit.
        if want:
            monitored = {cm.cert_key(h) for h in cm.effective_hosts(_cfg())}
            data = await asyncio.to_thread(cm.load_results)
            monitored |= {cm.cert_key(r) for r in data.get("results") or []}
            if key not in monitored and key not in ignored:
                raise HTTPException(status_code=404, detail="Host is not monitored")
            if key not in ignored and len(ignored) >= cm.MAX_IGNORED:
                raise HTTPException(status_code=400, detail=f"At most {cm.MAX_IGNORED} ignored certs")
            # Record who ignored it and when.
            actor = ((sess or {}).get("user", {}) or {}).get("username") or ""
            ignored[key] = {"by": str(actor)[:120],
                            "at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")}
        # Un-ignoring: just drop it.
        else:
            ignored.pop(key, None)
        # Save, log, re-check alerts in the background and return the new list.
        await _save_ignored(ignored)
        logger.info("[certmon] %s %s", "ignore" if want else "un-ignore", key)
        asyncio.create_task(_evaluate_alerts())
        return {"status": "ok", "key": key, "ignored": want, "ignored_hosts": ignored}

    # ── alert rules (breach + recovery digests; see cert_monitor_alerts) ──
    # List the alert rules plus the options the rule editor needs.
    @app.get("/api/certmon/alerts/rules")
    async def certmon_alert_rules(request: Request):
        """Return the rules, trigger types/labels, service names and the default threshold."""
        _guard(request)
        return {"rules": cma.get_rules(hub), "triggers": list(cma.TRIGGERS),
                "trigger_labels": cma.TRIGGER_LABELS, "services": cma.service_names(),
                "default_threshold_days": cma.DEFAULT_THRESHOLD_DAYS}

    async def _body(request):
        """Return the request's JSON body, or raise 400 if it isn't a JSON object."""
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = None
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="JSON object expected")
        return body

    # Create an alert rule.
    @app.post("/api/certmon/alerts/rules")
    async def certmon_alert_rule_create(request: Request):
        """Create a new alert rule (up to the rule limit) and save it."""
        _guard(request)
        body = await _body(request)
        rules = cma.get_rules(hub)
        if len(rules) >= cma.MAX_RULES:
            raise HTTPException(status_code=400, detail=f"At most {cma.MAX_RULES} rules")
        # Clean and save the new rule; evaluate it right away if enabled.
        rule = cma.clean_rule(body)
        rules.append(rule)
        await cma.save_rules(hub, rules)
        if rule["enabled"]:
            asyncio.create_task(_evaluate_alerts())
        return {"saved": True, "rule": rule}

    # Update an alert rule.
    @app.put("/api/certmon/alerts/rules/{rid}")
    async def certmon_alert_rule_update(rid: str, request: Request):
        """Replace rule ``rid`` with the cleaned body; 404 if it doesn't exist."""
        _guard(request)
        body = await _body(request)
        rules = cma.get_rules(hub)
        # Find the rule, clean and save the new version.
        for i, r in enumerate(rules):
            if r.get("id") == rid:
                rules[i] = cma.clean_rule(body, r)
                await cma.save_rules(hub, rules)
                # A changed trigger resets the rule's alert state.
                if rules[i]["trigger"] != r.get("trigger"):
                    async with alert_lock:
                        await asyncio.to_thread(cma.reset_rule_state, rid)
                # Re-evaluate in the background if the rule is enabled.
                if rules[i]["enabled"]:
                    asyncio.create_task(_evaluate_alerts())
                return {"saved": True, "rule": rules[i]}
        raise HTTPException(status_code=404, detail="Rule not found")

    # Delete an alert rule.
    @app.delete("/api/certmon/alerts/rules/{rid}")
    async def certmon_alert_rule_delete(rid: str, request: Request):
        """Delete rule ``rid``; report whether anything was removed."""
        _guard(request)
        rules = cma.get_rules(hub)
        keep = [r for r in rules if r.get("id") != rid]
        removed = len(keep) != len(rules)
        if removed:
            await cma.save_rules(hub, keep)
        return {"removed": removed}

    # Send a test alert for one rule.
    @app.post("/api/certmon/alerts/rules/{rid}/test")
    async def certmon_alert_rule_test(rid: str, request: Request):
        """Send a test digest for rule ``rid`` to its recipients using the current results."""
        _guard(request)
        # The rule must exist and have recipients.
        rule = next((r for r in cma.get_rules(hub) if r.get("id") == rid), None)
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
        if not rule.get("recipients"):
            raise HTTPException(status_code=400, detail="This rule has no recipients")
        # Build the same view the real evaluation sees (shared-tenant LE rows
        # only, see _evaluate_alerts) and send the test; a send failure is a 400.
        data = await asyncio.to_thread(cm.load_results)
        results = cm.scope_le_rows(_view(data.get("results"), _dt.datetime.now(_dt.timezone.utc)))
        if not await cma.send_test(hub, rule, cm.active_results(results)):
            raise HTTPException(status_code=400, detail="Send failed — check Setup → Notifications")
        return {"sent": True, "to": rule["recipients"]}

    async def _tick():
        """One scheduler tick: run a check when due (the monitor is enabled OR an
        LE cert has been pushed), otherwise just evaluate the alert rules."""
        data = await asyncio.to_thread(cm.load_results)
        reason = _due_reason(data, _le_entries())
        if reason:
            await _run(reason)
        elif _cfg()["enabled"]:
            await _evaluate_alerts(data)

    # Exposed for tests (and diagnostics) to drive one tick directly.
    app.state.certmon_tick = _tick

    async def _scheduler():
        """Background loop: one ``_tick`` every SCHEDULER_TICK_S."""
        # Give the hub a minute to start up first.
        await asyncio.sleep(60)
        while True:
            try:
                await _tick()
            # Cancellation stops the loop; other errors are logged and the loop goes on.
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                logger.warning("[certmon] scheduler tick failed: %s", e)
            # Wait for the next tick.
            await asyncio.sleep(SCHEDULER_TICK_S)

    async def _start_scheduler():
        """Start the scheduler task once (on app startup)."""
        try:
            if runtime["scheduler"] is None:
                runtime["scheduler"] = asyncio.create_task(_scheduler())
        except Exception as e:  # noqa: BLE001
            logger.warning("[certmon] scheduler start failed: %s", e)

    async def _stop_scheduler():
        """Cancel the scheduler task (on app shutdown)."""
        t = runtime.get("scheduler")
        if t:
            t.cancel()

    # Tie the scheduler to the app's startup and shutdown.
    app.router.on_startup.append(_start_scheduler)
    app.router.on_shutdown.append(_stop_scheduler)
