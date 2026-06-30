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