"""\"File a Bug\" report store for the LM Hub (WebUI footer → ab artifacts)."""

# Postpone evaluation of type hints so annotations are never evaluated at runtime.
from __future__ import annotations

# base64 converts screenshots between data-URL text and binary image files.
import base64
# json reads/writes each report's report.json metadata file.
import json
# Standard-library logging for store/load/status messages.
import logging
# os builds artifact paths and checks/creates directories.
import os
# time.time() timestamps reports.
import time
# uuid generates a random id for each new report.
import uuid

# Use the hub's main logger so [bug-report] lines appear in GET_LOGS scans.
logger = logging.getLogger("Hub")


class HubBugStoreMixin:
    """Persist WebUI-submitted bug reports (explanation + console + HTML +
    screenshot) under ``<data_dir>/bugs/<id>/`` and index them in memory so
    ab can enumerate (GET_BUG_REPORTS), pull full artifacts
    (GET_BUG_REPORT) and mark filed (MARK_BUG_FILED). State
    (``self.bug_dir`` / ``self.bug_reports`` / ``self.bug_report_limit``) is
    owned by ``LabManagerHub.__init__``."""

    # ── "File a Bug" report store ────────────────────────────────────────────
    # The WebUI footer button POSTs an explanation + console + HTML + screenshot
    # to /api/bug-report. The full artifacts are written under data_dir/bugs/<id>/
    # and a short [bug-report] marker line is logged (so ab's GET_LOGS scan
    # finds it). ab enumerates via GET_BUG_REPORTS, pulls full artifacts via
    # GET_BUG_REPORT (for AI-fix context), and marks filed via MARK_BUG_FILED so
    # the same report is never filed twice.
    def _store_bug_report(self, payload: dict) -> str:
        """Save a submitted bug/feature report to disk and the in-memory index; returns its id
        ("" on failure).
        """
        # Short random id (12 hex chars) used as the report's folder name.
        rid = uuid.uuid4().hex[:12]
        # Each report gets its own folder under the bug directory.
        d = os.path.join(self.bug_dir, rid)
        # Create the folder; without it nothing can be stored, so give up.
        try:
            os.makedirs(d, exist_ok=True)
        except Exception as e:
            logger.warning(f"[bug-report] could not create report dir {d}: {e}")
            return ""
        # Free-text description and severity (default medium).
        explanation = str(payload.get("explanation") or "")
        severity = str(payload.get("severity") or "medium")
        # "bug" (default, incl. all legacy reports) or "feature" — set by the
        # WebUI "Bug/Feature Request" footer modal's checkbox. ab files a
        # feature request as a GitHub ``enhancement`` issue (no auto-fix).
        rtype = str(payload.get("type") or "bug").strip().lower() or "bug"
        # Anything other than bug/feature is treated as a bug.
        if rtype not in ("bug", "feature"):
            rtype = "bug"
        # Extra page context the WebUI captured (URL, user agent, etc.).
        context = payload.get("context") or {}
        # Tenant attribution for the read-only tenant-admin view. The route
        # resolves this server-side (session tenant, else the header tenant
        # picker) and injects it — the browser payload is NOT trusted for it.
        # Untagged (legacy / no active tenant) reports stay Global-Admin-only.
        tenant_id = str(payload.get("tenant_id") or "").strip()
        # Optional Request-Assistant fields (absent on one-shot reports): a short
        # title (ab prefers it for the issue title), the structured spec and the
        # assistant session id. Older ab ignores them.
        title = " ".join(str(payload.get("title") or "").split())[:200]
        # Optional structured request spec and assistant session id (capped length).
        request_spec = payload.get("request_spec")
        assistant_session = str(payload.get("assistant_session") or "")[:64]
        # Persist the structured metadata + the captured text artifacts.
        report_json = {
            "id": rid, "explanation": explanation, "severity": severity,
            "type": rtype, "context": context, "filed": False, "issue_url": "",
            "tenant_id": tenant_id, "ts": time.time(),
        }
        # Only include the optional fields when they were supplied.
        if title:
            report_json["title"] = title
        if isinstance(request_spec, dict) and request_spec:
            report_json["request_spec"] = request_spec
        if assistant_session:
            report_json["assistant_session"] = assistant_session
        # Write the metadata, browser console log and page HTML as separate files.
        try:
            with open(os.path.join(d, "report.json"), "w") as f:
                json.dump(report_json, f, indent=2)
            with open(os.path.join(d, "console.log"), "w") as f:
                f.write(str(payload.get("console_logs") or ""))
            with open(os.path.join(d, "dom.html"), "w") as f:
                f.write(str(payload.get("html") or ""))
        # A write failure is logged; the in-memory entry below is still created.
        except Exception as e:
            logger.warning(f"[bug-report] failed writing artifacts for {rid}: {e}")
        # Screenshot is a data URL; decode to bytes so it's a real PNG/JPEG file.
        # The screenshot arrives as a "data:image/...;base64,..." string.
        shot = payload.get("screenshot")
        if isinstance(shot, str) and shot.startswith("data:"):
            # Split off the header, pick the file extension, and write the decoded image bytes.
            try:
                header, b64 = shot.split(",", 1)
                ext = "png" if "image/png" in header else "jpg"
                with open(os.path.join(d, f"screenshot.{ext}"), "wb") as f:
                    f.write(base64.b64decode(b64))
                report_json["screenshot_file"] = f"screenshot.{ext}"
            # A bad screenshot is logged but does not fail the report.
            except Exception as e:
                logger.warning(f"[bug-report] failed decoding screenshot for {rid}: {e}")
        # In-memory index (capped). Holds the metadata ab lists; full
        # artifacts are read from disk on demand by _get_bug_report.
        self.bug_reports[rid] = {
            "id": rid, "summary": (title or explanation)[:120], "severity": severity,
            "type": rtype, "ts": report_json["ts"], "filed": False, "issue_url": "",
            "tenant_id": tenant_id,
            "context": context, "has_screenshot": "screenshot_file" in report_json,
        }
        # Over the cap: evict the oldest reports from memory (their files remain on disk).
        while len(self.bug_reports) > self.bug_report_limit:
            oldest = min(self.bug_reports, key=lambda k: self.bug_reports[k].get("ts", 0))
            self.bug_reports.pop(oldest, None)
        # Authoritative "report is on disk and ready for ab" trace line.
        logger.info(
            f"[bug-report] stored id={rid} type={rtype} severity={severity} "
            f"console={len(str(payload.get('console_logs') or ''))} "
            f"html={len(str(payload.get('html') or ''))} "
            f"screenshot={report_json.get('screenshot_file') or 'none'} "
            f"dir={d} index_size={len(self.bug_reports)}"
        )
        # Return the new report id.
        return rid

    def _list_bug_reports(self) -> list:
        """Return copies of every indexed report's metadata (for GET_BUG_REPORTS)."""
        # Copy each dict so callers cannot mutate the index.
        return [dict(v) for v in self.bug_reports.values()]

    def _get_bug_report(self, rid: str) -> dict:
        """Return a report's metadata plus its on-disk artifacts, or {} if unknown."""
        # Need both an index entry and the report folder.
        meta = self.bug_reports.get(rid)
        d = os.path.join(self.bug_dir, rid)
        if not meta or not os.path.isdir(d):
            return {}
        # Start from the indexed metadata.
        out = {
            "id": rid, "summary": meta.get("summary", ""), "severity": meta.get("severity", ""),
            "type": meta.get("type", "bug"), "ts": meta.get("ts", 0), "filed": meta.get("filed", False),
            "issue_url": meta.get("issue_url", ""), "context": meta.get("context", {}),
            "tenant_id": meta.get("tenant_id", ""),
            # status: "" (new) → "filed" (issue opened) → "fixed" (ab closed it).
            "status": meta.get("status", ("filed" if meta.get("filed") else "")),
            "fixed_at": meta.get("fixed_at", 0),
        }
        # Attach each text artifact that exists, keyed report_json / console / dom.
        for name in ("report.json", "console.log", "dom.html"):
            p = os.path.join(d, name)
            if os.path.exists(p):
                # An unreadable file is skipped (logged at debug).
                try:
                    with open(p, "r") as f:
                        out[name.replace(".json", "_json").replace(".log", "").replace(".html", "")] = f.read()
                except Exception:
                    logger.debug("bug-report: failed reading %s for %s", p, rid, exc_info=True)
        # Screenshot back as a data URL so ab can pass it to the AI as
        # context if useful (kept out of the public GitHub issue).
        # Attach the screenshot (PNG or JPEG, whichever exists) as a data URL.
        for ext in ("png", "jpg"):
            p = os.path.join(d, f"screenshot.{ext}")
            if os.path.exists(p):
                # Read and base64-encode the image bytes.
                try:
                    with open(p, "rb") as f:
                        b64 = base64.b64encode(f.read()).decode()
                    mime = "image/png" if ext == "png" else "image/jpeg"
                    out["screenshot_b64"] = f"data:{mime};base64,{b64}"
                # An unreadable image is skipped.
                except Exception:
                    logger.debug("bug-report: failed reading %s for %s", p, rid, exc_info=True)
                # Only one screenshot is expected, so stop after the first found.
                break
        # Return the assembled report.
        return out

    def warm_load_bug_reports(self) -> None:
        """Rebuild the in-memory bug-report index from the artifacts already on
        disk (``<data_dir>/bugs/<id>/report.json``) at boot — otherwise
        GET_BUG_REPORTS returns empty after a restart and ab can't enumerate
        prior reports (and may re-file duplicates). Capped, most-recent first.
        Best-effort; never raises."""
        # Any failure just leaves the index empty; boot must not be blocked.
        try:
            # glob finds every report.json under the bug directory.
            import glob as _glob
            # (timestamp, report) pairs read from disk.
            entries = []
            for p in _glob.glob(os.path.join(self.bug_dir, "*", "report.json")):
                # Skip any individual report file that is unreadable.
                try:
                    with open(p) as f:
                        r = json.load(f) or {}
                    if r.get("id"):
                        # Only keep reports that have an id.
                        entries.append((float(r.get("ts", 0) or 0), r))
                except Exception:  # noqa: BLE001
                    continue
            # Newest first, then load up to the cap into the index.
            entries.sort(key=lambda e: e[0], reverse=True)
            for _ts, r in entries[: self.bug_report_limit]:
                self.bug_reports[r["id"]] = {
                    "id": r["id"], "summary": str(r.get("title") or r.get("explanation", ""))[:120],
                    "severity": r.get("severity", "medium"), "type": r.get("type", "bug"),
                    "ts": r.get("ts", 0),
                    "filed": bool(r.get("filed")), "issue_url": r.get("issue_url", ""),
                    "status": r.get("status", ("filed" if r.get("filed") else "")),
                    "fixed_at": r.get("fixed_at", 0),
                    "context": r.get("context") or {},
                    "tenant_id": str(r.get("tenant_id") or ""),
                    "has_screenshot": bool(r.get("screenshot_file")),
                }
            # Log how many were restored.
            if self.bug_reports:
                logger.info("bug_reports: warm-loaded %d report(s) from disk", len(self.bug_reports))
        # Log quietly and continue.
        except Exception as e:  # noqa: BLE001
            logger.debug("bug_reports warm load skipped: %s", e)

    def _mark_bug_filed(self, rid: str, issue_url: str) -> bool:
        """Mark a report as filed with its GitHub issue URL."""
        # Delegates to the shared status updater.
        return self._update_bug_status(rid, filed=True, issue_url=issue_url, status="filed")

    def _mark_bug_in_progress(self, rid: str, issue_url: str = "") -> bool:
        """ab has STARTED actively working this report's GitHub issue (fix /
        build attempts underway) → mark it 'in_progress' so the LM UI shows the
        user it is being worked on, distinct from the passive 'filed' (issue
        opened, not yet worked) and terminal 'fixed'. filed stays True. Sent by
        ab at the top of process_single_issue once the issue is deemed
        actionable; the eventual MARK_BUG_FIXED/CLOSED overwrites it."""
        return self._update_bug_status(rid, filed=True, issue_url=issue_url or None,
                                       status="in_progress")

    def _mark_bug_duplicate(self, rid: str, issue_url: str) -> bool:
        """ab detected this report is a duplicate/recurrence of an EXISTING
        GitHub issue instead of filing a fresh one → mark it 'duplicate' + link that
        same issue. filed=True so it isn't re-filed and (for features) isn't gated.
        The issue_url is recorded so the MARK_BUG_FIXED cascade later flips this
        report to 'fixed' when ab closes the shared issue."""
        return self._update_bug_status(rid, filed=True, issue_url=issue_url, status="duplicate")

    @staticmethod
    def _bug_feature_gated(r: dict) -> bool:
        """True if this report is a feature request that an admin has NOT yet
        approved — ab must not file/work it. Bugs are never gated; a feature
        that's already approved/filed/fixed is not gated."""
        # Bugs never need approval.
        if (r.get("type") or "bug") != "feature":
            return False
        # Features are gated until approved or already progressed/filed.
        st = str(r.get("status") or "").lower()
        return not (st in ("approved", "in_progress", "filed", "fixed") or bool(r.get("filed")))

    def _approve_bug_report(self, rid: str) -> bool:
        """Admin approved a feature request → mark it 'approved' so GET_BUG_REPORTS
        exposes it and ab may file the GitHub issue and work it. No-op-safe on
        bugs (they never need approval)."""
        return self._update_bug_status(rid, status="approved")

    def _mark_bug_closed(self, rid: str, issue_url: str = "") -> bool:
        """The GitHub issue was closed WITHOUT a fix → mark it 'closed' so the LM UI
        shows a distinct "Closed (not fixed)" state instead of a misleading "Fixed"."""
        return self._update_bug_status(rid, filed=True, issue_url=issue_url or None,
                                       status="closed")

    def _mark_bug_fixed(self, rid: str, issue_url: str = "") -> bool:
        """ab closed the GitHub issue for this report → mark it 'fixed' so the
        LM bug-reports UI shows Fixed + the issue link.

        A recurrence dedups several reports onto ONE GitHub issue (each reopens it /
        adds evidence), but ab only passes the single report id embedded in the
        issue body. So the sibling recurrence reports would stay stuck at 'filed' even
        though the work is done. Mark every report sharing this issue_url fixed too."""
        # Imported locally under an alias; gives one timestamp for all updates.
        import time as _t
        now = _t.time()
        # Mark this report fixed.
        ok = self._update_bug_status(rid, status="fixed", issue_url=issue_url or None, fixed_at=now)
        # The issue URL to match siblings against (passed in, or the one already stored).
        url = (issue_url or (self.bug_reports.get(rid) or {}).get("issue_url") or "").strip()
        # Mark every other report sharing the same issue as fixed too.
        if url:
            for other_rid, meta in list(self.bug_reports.items()):
                # Skip the report we already updated.
                if other_rid == rid:
                    continue
                # Same issue and not yet fixed: update it and log the cascade.
                if (meta.get("issue_url") or "").strip() == url and str(meta.get("status") or "").lower() != "fixed":
                    self._update_bug_status(other_rid, status="fixed", fixed_at=now)
                    logger.info(f"[bug-report] MARK_BUG_FIXED cascaded to sibling {other_rid} (same issue {url})")
        # Return whether the primary report was found.
        return ok

    def _update_bug_status(self, rid: str, *, filed=None, status=None,
                           issue_url=None, fixed_at=None) -> bool:
        """Update a report's filed/status/issue_url/fixed_at in the in-memory index
        AND persist to report.json so it survives a hub restart. Only sets the fields
        passed (issue_url=None leaves the existing one)."""
        # Unknown report id.
        meta = self.bug_reports.get(rid)
        if not meta:
            return False
        # Update only the fields the caller supplied.
        if filed is not None:
            meta["filed"] = bool(filed)
        if status is not None:
            meta["status"] = status
        if issue_url:
            meta["issue_url"] = issue_url
        if fixed_at is not None:
            meta["fixed_at"] = fixed_at
        # Mirror the updated fields into the report's report.json on disk.
        p = os.path.join(self.bug_dir, rid, "report.json")
        try:
            # Read, update and rewrite the file.
            with open(p, "r") as f:
                rpt = json.load(f)
            for k in ("filed", "status", "issue_url", "fixed_at"):
                if k in meta:
                    rpt[k] = meta[k]
            with open(p, "w") as f:
                json.dump(rpt, f, indent=2)
        # Persist failure is logged; the in-memory update still stands.
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[bug-report] could not persist status for {rid}: {e}")
        # The report was found and updated.
        return True

    def _delete_bug_report(self, rid: str) -> bool:
        """Remove a bug report from the in-memory index and delete its on-disk
        artifacts (``<data_dir>/bugs/<id>/`` — report.json, console.log,
        dom.html, screenshot). Returns True if anything was removed (index
        hit OR a stale dir existed), False if the id was unknown. Best-effort
        on the rmtree: a missing/locked dir still counts as removed-from-
        index so the WebUI list refresh shows it gone. The public GitHub
        issue (if ab already filed one) is NOT touched — only the hub's
        local copy of the captured artifacts."""
        # No id given: nothing to delete.
        if not rid:
            return False
        # Remember whether it was indexed, then drop it from the index.
        existed = rid in self.bug_reports
        self.bug_reports.pop(rid, None)
        # Delete the artifact folder if present.
        d = os.path.join(self.bug_dir, rid)
        removed_dir = False
        if os.path.isdir(d):
            try:
                # shutil.rmtree removes the folder and everything in it.
                import shutil
                shutil.rmtree(d)
                removed_dir = True
            # A locked/missing folder is logged but not fatal.
            except Exception as e:
                logger.warning(f"[bug-report] could not remove artifact dir {d}: {e}")
        # Report success if either the index entry or the folder existed.
        if existed or removed_dir:
            logger.info(f"[bug-report] deleted id={rid} index_size={len(self.bug_reports)}")
            return True
        # Unknown id: nothing was removed.
        return False
