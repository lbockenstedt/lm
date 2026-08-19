"""_tail_lines seek-tails a file's last N lines without reading the whole file.

collect_all_logs / collect_error_logs call it on every GET_LOGS poll; once
hub.log grew into the 100s of MB the old full-file deque walk pushed the
AppBuilder round-trip past its 20s timeout. These tests pin the semantics
(match the old ``deque(f, maxlen=n)`` tail) and the edge cases.
"""
from collections import deque

from log_redaction import _tail_lines


def test_matches_deque_tail(tmp_path):
    p = tmp_path / "big.log"
    p.write_text("".join(f"line {i} content\n" for i in range(50000)))
    with p.open() as f:
        old = [ln.strip() for ln in deque(f, maxlen=500)]
    old = [ln for ln in old if ln]
    assert _tail_lines(str(p), 500) == old
    assert len(old) == 500


def test_no_trailing_newline(tmp_path):
    p = tmp_path / "t.log"
    p.write_text("a\nb\nc")
    assert _tail_lines(str(p), 500) == ["a", "b", "c"]
    assert _tail_lines(str(p), 2) == ["b", "c"]


def test_fewer_lines_than_n(tmp_path):
    p = tmp_path / "t.log"
    p.write_text("only one\n")
    assert _tail_lines(str(p), 500) == ["only one"]


def test_empty_file(tmp_path):
    p = tmp_path / "e.log"
    p.write_text("")
    assert _tail_lines(str(p), 500) == []


def test_missing_file_is_safe(tmp_path):
    assert _tail_lines(str(tmp_path / "nope.log"), 500) == []


def test_spans_multiple_read_blocks(tmp_path):
    # Force the backward-read loop to iterate several blocks (long lines).
    p = tmp_path / "wide.log"
    p.write_text("".join(f"{i}:" + "x" * 5000 + "\n" for i in range(200)))
    out = _tail_lines(str(p), 50, _block=4096)
    assert len(out) == 50
    assert out[-1].startswith("199:")
    assert out[0].startswith("150:")
