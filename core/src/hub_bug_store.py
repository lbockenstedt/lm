"""\"File a Bug\" report store for the LM Hub (WebUI footer → bugfixer artifacts)."""

from __future__ import annotations

import base64
import json
import logging
import os
import time
import uuid

logger = logging.getLogger("Hub")


class HubBugStoreMixin:
    """Persist WebUI-submitted bug reports (explanation + console + HTML +
    screenshot) under ``<data_dir>/bugs/<id>/`` and index them in memory so
    bugfixer can enumerate (GET_BUG_REPORTS), pull full artifacts
    (GET_BUG_REPORT) and mark filed (MARK_BUG_FILED). State
    (``self.bug_dir`` / ``self.bug_reports`` / ``self.bug_report_limit``) is
    owned by ``LabManagerHub.__init__``."""

    # ── "File a Bug" report store ────────────────────────────────────────────
    # The WebUI footer button POSTs an explanation + console + HTML + screenshot
    # to /api/bug-report. The full artifacts are written under data_dir/bugs/<id>/
    # and a short [bug-report] marker line is logged (so bugfixer's GET_LOGS scan
    # finds it). bugfixer enumerates via GET_BUG_REPORTS, pulls full artifacts via
    # GET_BUG_REPORT (for AI-fix context), and marks filed via MARK_BUG_FILED so
    # the same report is never filed twice.
    def _store_bug_report(self, payload: dict) -> str:
        rid = uuid.uuid4().hex[:12]
        d = os.path.join(self.bug_dir, rid)
        try:
            os.makedirs(d, exist_ok=True)
        except Exception as e:
            logger.warning(f"[bug-report] could not create report dir {d}: {e}")
            return ""
        explanation = str(payload.get("explanation") or "")
        severity = str(payload.get("severity") or "medium")
        # "bug" (default, incl. all legacy reports) or "feature" — set by the
        # WebUI "Bug/Feature Request" footer modal's checkbox. bugfixer files a
        # feature request as a GitHub ``enhancement`` issue (no auto-fix).
        rtype = str(payload.get("type") or "bug").strip().lower() or "bug"
        if rtype not in ("bug", "feature"):
            rtype = "bug"
        context = payload.get("context") or {}
        # Persist the structured metadata + the captured text artifacts.
        report_json = {
            "id": rid, "explanation": explanation, "severity": severity,
            "type": rtype, "context": context, "filed": False, "issue_url": "",
            "ts": time.time(),
        }
        try:
            with open(os.path.join(d, "report.json"), "w") as f:
                json.dump(report_json, f, indent=2)
            with open(os.path.join(d, "console.log"), "w") as f:
                f.write(str(payload.get("console_logs") or ""))
            with open(os.path.join(d, "dom.html"), "w") as f:
                f.write(str(payload.get("html") or ""))
        except Exception as e:
            logger.warning(f"[bug-report] failed writing artifacts for {rid}: {e}")
        # Screenshot is a data URL; decode to bytes so it's a real PNG/JPEG file.
        shot = payload.get("screenshot")
        if isinstance(shot, str) and shot.startswith("data:"):
            try:
                header, b64 = shot.split(",", 1)
                ext = "png" if "image/png" in header else "jpg"
                with open(os.path.join(d, f"screenshot.{ext}"), "wb") as f:
                    f.write(base64.b64decode(b64))
                report_json["screenshot_file"] = f"screenshot.{ext}"
            except Exception as e:
                logger.warning(f"[bug-report] failed decoding screenshot for {rid}: {e}")
        # In-memory index (capped). Holds the metadata bugfixer lists; full
        # artifacts are read from disk on demand by _get_bug_report.
        self.bug_reports[rid] = {
            "id": rid, "summary": explanation[:120], "severity": severity,
            "type": rtype, "ts": report_json["ts"], "filed": False, "issue_url": "",
            "context": context, "has_screenshot": "screenshot_file" in report_json,
        }
        while len(self.bug_reports) > self.bug_report_limit:
            oldest = min(self.bug_reports, key=lambda k: self.bug_reports[k].get("ts", 0))
            self.bug_reports.pop(oldest, None)
        # Authoritative "report is on disk and ready for bugfixer" trace line.
        logger.info(
            f"[bug-report] stored id={rid} type={rtype} severity={severity} "
            f"console={len(str(payload.get('console_logs') or ''))} "
            f"html={len(str(payload.get('html') or ''))} "
            f"screenshot={report_json.get('screenshot_file') or 'none'} "
            f"dir={d} index_size={len(self.bug_reports)}"
        )
        return rid

    def _list_bug_reports(self) -> list:
        return [dict(v) for v in self.bug_reports.values()]

    def _get_bug_report(self, rid: str) -> dict:
        meta = self.bug_reports.get(rid)
        d = os.path.join(self.bug_dir, rid)
        if not meta or not os.path.isdir(d):
            return {}
        out = {
            "id": rid, "summary": meta.get("summary", ""), "severity": meta.get("severity", ""),
            "type": meta.get("type", "bug"), "ts": meta.get("ts", 0), "filed": meta.get("filed", False),
            "issue_url": meta.get("issue_url", ""), "context": meta.get("context", {}),
        }
        for name in ("report.json", "console.log", "dom.html"):
            p = os.path.join(d, name)
            if os.path.exists(p):
                try:
                    with open(p, "r") as f:
                        out[name.replace(".json", "_json").replace(".log", "").replace(".html", "")] = f.read()
                except Exception:
                    logger.debug("bug-report: failed reading %s for %s", p, rid, exc_info=True)
        # Screenshot back as a data URL so bugfixer can pass it to the AI as
        # context if useful (kept out of the public GitHub issue).
        for ext in ("png", "jpg"):
            p = os.path.join(d, f"screenshot.{ext}")
            if os.path.exists(p):
                try:
                    with open(p, "rb") as f:
                        b64 = base64.b64encode(f.read()).decode()
                    mime = "image/png" if ext == "png" else "image/jpeg"
                    out["screenshot_b64"] = f"data:{mime};base64,{b64}"
                except Exception:
                    logger.debug("bug-report: failed reading %s for %s", p, rid, exc_info=True)
                break
        return out

    def warm_load_bug_reports(self) -> None:
        """Rebuild the in-memory bug-report index from the artifacts already on
        disk (``<data_dir>/bugs/<id>/report.json``) at boot — otherwise
        GET_BUG_REPORTS returns empty after a restart and bugfixer can't enumerate
        prior reports (and may re-file duplicates). Capped, most-recent first.
        Best-effort; never raises."""
        try:
            import glob as _glob
            entries = []
            for p in _glob.glob(os.path.join(self.bug_dir, "*", "report.json")):
                try:
                    with open(p) as f:
                        r = json.load(f) or {}
                    if r.get("id"):
                        entries.append((float(r.get("ts", 0) or 0), r))
                except Exception:  # noqa: BLE001
                    continue
            entries.sort(key=lambda e: e[0], reverse=True)
            for _ts, r in entries[: self.bug_report_limit]:
                self.bug_reports[r["id"]] = {
                    "id": r["id"], "summary": str(r.get("explanation", ""))[:120],
                    "severity": r.get("severity", "medium"), "type": r.get("type", "bug"),
                    "ts": r.get("ts", 0),
                    "filed": bool(r.get("filed")), "issue_url": r.get("issue_url", ""),
                    "context": r.get("context") or {},
                    "has_screenshot": bool(r.get("screenshot_file")),
                }
            if self.bug_reports:
                logger.info("bug_reports: warm-loaded %d report(s) from disk", len(self.bug_reports))
        except Exception as e:  # noqa: BLE001
            logger.debug("bug_reports warm load skipped: %s", e)

    def _mark_bug_filed(self, rid: str, issue_url: str) -> bool:
        meta = self.bug_reports.get(rid)
        if not meta:
            return False
        meta["filed"] = True
        meta["issue_url"] = issue_url or ""
        # Persist to report.json too so the filed flag survives a hub restart.
        p = os.path.join(self.bug_dir, rid, "report.json")
        try:
            with open(p, "r") as f:
                rpt = json.load(f)
            rpt["filed"] = True
            rpt["issue_url"] = issue_url or ""
            with open(p, "w") as f:
                json.dump(rpt, f, indent=2)
        except Exception as e:
            logger.warning(f"[bug-report] could not persist filed flag for {rid}: {e}")
        return True

    def _delete_bug_report(self, rid: str) -> bool:
        """Remove a bug report from the in-memory index and delete its on-disk
        artifacts (``<data_dir>/bugs/<id>/`` — report.json, console.log,
        dom.html, screenshot). Returns True if anything was removed (index
        hit OR a stale dir existed), False if the id was unknown. Best-effort
        on the rmtree: a missing/locked dir still counts as removed-from-
        index so the WebUI list refresh shows it gone. The public GitHub
        issue (if bugfixer already filed one) is NOT touched — only the hub's
        local copy of the captured artifacts."""
        if not rid:
            return False
        existed = rid in self.bug_reports
        self.bug_reports.pop(rid, None)
        d = os.path.join(self.bug_dir, rid)
        removed_dir = False
        if os.path.isdir(d):
            try:
                import shutil
                shutil.rmtree(d)
                removed_dir = True
            except Exception as e:
                logger.warning(f"[bug-report] could not remove artifact dir {d}: {e}")
        if existed or removed_dir:
            logger.info(f"[bug-report] deleted id={rid} index_size={len(self.bug_reports)}")
            return True
        return False
