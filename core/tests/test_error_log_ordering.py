"""collect_error_logs must return lines sorted ascending by timestamp so the
WebUI's ``.slice().reverse()`` (main.js) yields globally newest-first across all
sources (hub deque, agent_logs, disk files). Without the sort the WebUI
reverses the concatenated blob per-source, so a newer hub line lands *below* an
older disk line. Also: non-timestamped lines (traceback continuations) sort to
the bottom after the reverse, not the top.
"""
import main  # noqa: E402  (core/src on sys.path via conftest)


class _Hub:
    """collect_error_logs only reads self.logs + self.agent_logs (+ /var/log/lm,
    gated by os.path.exists). Populate those two; disk noise, if any, sorts by
    its own timestamps and doesn't disturb the relative order asserted here."""
    def __init__(self, logs, agent_logs):
        self.logs = logs
        self.agent_logs = agent_logs


def _reversed_logs(hub):
    # Mirror the WebUI: main.js does `(data.logs || []).slice().reverse()`.
    return list(main.LabManagerHub.collect_error_logs(hub)["logs"])[::-1]


def _pos(ordered, marker):
    return next(i for i, line in enumerate(ordered) if marker in line)


def test_collect_error_logs_newest_first_globally_across_sources():
    # Hub new (12:00) is NEWER than the agent line (11:00) which is newer than
    # hub old (10:00). Sources are concatenated hub→agent in the raw list, so
    # without a global timestamp sort a plain reverse would keep hub-old above
    # hub-new (both hub) and the agent line last — wrong.
    h = _Hub(
        logs=[
            "2026-06-30 10:00:00,111 - Hub - ERROR - hub old MARKER_HUB_OLD",
            "2026-06-30 12:00:00,222 - Hub - ERROR - hub new MARKER_HUB_NEW",
        ],
        agent_logs={"bugfixer": [
            "2026-06-30 11:00:00,333 - BugFixer - ERROR - agent MARKER_AGENT",
        ]},
    )
    ordered = _reversed_logs(h)
    assert _pos(ordered, "MARKER_HUB_NEW") < _pos(ordered, "MARKER_AGENT")
    assert _pos(ordered, "MARKER_AGENT") < _pos(ordered, "MARKER_HUB_OLD")


def test_collect_error_logs_non_timestamped_lines_sort_to_bottom():
    # A traceback continuation (no leading timestamp) must not crowd the top.
    h = _Hub(
        logs=[
            "2026-06-30 10:00:00,000 - Hub - ERROR - timestamped MARKER_TS",
            "Traceback (most recent call last): MARKER_NOTS",
        ],
        agent_logs={},
    )
    ordered = _reversed_logs(h)
    # After reverse: timestamped lines (newest-first) above non-timestamped.
    assert _pos(ordered, "MARKER_TS") < _pos(ordered, "MARKER_NOTS")


def test_collect_error_logs_excludes_uvicorn_error_logger_name():
    # The bare-word "error" regex false-positived on the uvicorn.error LOGGER
    # NAME, landing benign INFO lifecycle lines ("connection open") in the error
    # log. The (?<!\.) lookbehind excludes dotted logger names while still
    # matching real error lines.
    h = _Hub(
        logs=[
            "2026-07-08 01:25:51 - uvicorn.error - INFO - connection open",
            "2026-07-08 01:25:52 - Hub - ERROR - Request Timeout: abc after 5.0s",
            "2026-07-08 01:25:53 - Hub - INFO - [sync-error] retry MARKER_SYNC",  # WARNING-worthy marker, has "error" via hyphen → still matches
        ],
        agent_logs={},
    )
    errs = list(main.LabManagerHub.collect_error_logs(h)["logs"])
    bodies = [e.split("] ", 1)[1] if e.startswith("[") else e for e in errs]
    assert not any("connection open" in b for b in bodies), bodies
    assert any("Request Timeout: abc" in b for b in bodies), bodies
    # "[sync-error]" has "error" preceded by a hyphen (not a dot) → still caught.
    assert any("MARKER_SYNC" in b for b in bodies), bodies


def test_collect_error_logs_dedupes_hub_buffer_and_disk_copies():
    # The hub's own records reach the list twice in production — once from
    # self.logs (the HubLogHandler buffer) and once from the hub.log disk read,
    # same canonical line. The dedup strips the ``[source] `` prefix and keeps
    # one copy. Simulate the double by putting the same canonical line in both
    # self.logs (as ``[hub]``) and agent_logs under a key that also prefixes
    # ``[hub]`` is not possible, so instead place the identical line twice in
    # self.logs — the dedup path is source-strip-then-key, exercised the same.
    dup_line = "2026-07-08 01:25:31 - Hub - ERROR - Request Timeout: dup-uuid after 5.0s"
    h = _Hub(
        logs=[dup_line, dup_line],
        agent_logs={},
    )
    errs = list(main.LabManagerHub.collect_error_logs(h)["logs"])
    matches = [e for e in errs if "dup-uuid" in e]
    assert len(matches) == 1, matches