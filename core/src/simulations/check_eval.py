"""Canonical monitored-check count evaluation for CS / Aruba Central.

CANONICAL SOURCE: cs/lm-spoke/src/check_eval.py
VENDORED — keep byte-identical (the body is import-free on purpose so a copy
drops into any tree unchanged):
  - cs/webui-local/app/check_eval.py       (CS standalone central box)
  - cs/webui-spoke/check_eval.py           (CS standalone spoke UI)
  - lm/core/src/simulations/check_eval.py  (LM hub core — SEPARATE repo)

Why this exists: the count-matching logic below was duplicated inline in four
separate deployments that share no Python import path (three CS sub-trees on
different boxes + the LM hub core in a different repo). The SAME type-silo bug
had to be fixed in all four before it stopped ramping the adaptive controller.
This is now the single source of truth for that logic; a divergence between the
copies is a bug. If you change one, change every copy — each tree has a
test_check_eval.py pinning the behaviour.

Scope: this returns the raw active count only. The INVERTED "firing == healthy"
semantics (a sim is SUPPOSED to produce the error, so a present condition is OK
and an absent one is the failure) stay in each CALLER, along with the other
per-caller concerns — site filtering, status-string casing, the diag log line,
and any extra result fields.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional


def normalize_counts(d: Optional[Mapping[str, Any]]) -> Dict[str, int]:
    """Fold a {name: count} map to stripped-lowercase keys, summing collisions.

    Aruba Central returns condition names with inconsistent casing/whitespace and
    monitored-check ids are user-entered, so both sides are normalised the same
    way — that is what lets a quota typed "DNS Server Failed to Respond" match
    Central's "dns server failed to respond".
    """
    out: Dict[str, int] = {}
    for k, v in (d or {}).items():
        kk = str(k).strip().lower()
        out[kk] = out.get(kk, 0) + int(v or 0)
    return out


def count_for_check(check: Mapping[str, Any],
                    alert_ci: Mapping[str, int],
                    insight_ci: Mapping[str, int]) -> int:
    """Active count for one monitored check.

    Matched case-insensitively across BOTH the alert and insight buckets: the
    check's own typed bucket first, then the other bucket as a fall-back. Central
    classifies some named conditions as INSIGHTS (e.g. "DNS Server Failed to
    Respond") while a sim-quota may be typed "alert"; reading only the typed
    bucket reported a live condition as absent and made the adaptive controller
    ramp forever and exhaust the client pool. A check with no/blank type is
    treated as an alert, matching the pollers' historical default.

    Pass PRE-normalised dicts (see normalize_counts) so a loop over many checks
    normalises each bucket once rather than once per check.
    """
    key = str(check.get("id") or "").strip().lower()
    if not key:
        return 0
    is_alert = (check.get("type") or "alert") == "alert"
    primary, other = (alert_ci, insight_ci) if is_alert else (insight_ci, alert_ci)
    return int(primary.get(key, 0) or other.get(key, 0) or 0)
