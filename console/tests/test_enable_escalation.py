"""Privilege escalation on an unprivileged (">") console prompt.

A prompt ending in ``>`` is UNPRIVILEGED (user EXEC) on Cisco IOS, HPE/Aruba
AOS-S and most network CLIs. The identity ``show`` commands are rejected there,
so a device we logged into perfectly well would still be reported as unknown.
The probe therefore sends ``enable`` and answers whatever the device asks for
until the prompt ends in ``#``.

Guards the two things that must NOT happen:
  * ``enable`` is never typed into a UNIX ``$``/``%`` shell, where it is
    meaningless (and on some appliances is a real, state-changing command);
  * an OPERATOR's already-open session that we escalated but do not log out of
    is dropped back to its original privilege level.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import fingerprint as fp  # noqa: E402


class _Chan:
    """Scripted serial line: a pre-loaded buffer plus per-write responses.

    ``responses`` is a list of ``(trigger_substring, reply)``; the first
    unconsumed trigger contained in a write() fires once. A trigger of ``""``
    matches a bare CR (what the probe sends to nudge the line)."""

    def __init__(self, banner="", responses=()):
        self.buf = bytearray(banner.encode())
        self.responses = list(responses)
        self.sent = []

    def read(self):
        out = bytes(self.buf[:256])
        del self.buf[:256]
        return out

    def write(self, b):
        s = b.decode(errors="replace")
        self.sent.append(s)
        for i, (trig, resp) in enumerate(self.responses):
            if trig is None:
                continue
            if trig in s:
                self.buf += resp.encode()
                self.responses[i] = (None, "")
                return

    def wrote(self, needle):
        return any(needle in s for s in self.sent)


def _run(banner, responses, credentials=None, cred_idx=0):
    ch = _Chan(banner, responses)
    ch.read()   # the banner is already in the transcript by the time we escalate
    return ch, fp._escalate_privilege(
        ch.read, ch.write, credentials if credentials is not None
        else [{"username": "admin", "password": "s3cret"}], cred_idx, banner)


# ── The happy paths ──────────────────────────────────────────────────────────
def test_enable_with_no_secret_reaches_privileged():
    # Plenty of devices have no separate enable secret: `enable` goes straight
    # to "#".
    ch, (tr, diag) = _run("\r\nswitch>", [("enable", "\r\nswitch#")])
    assert ch.wrote("enable")
    assert diag["escalated"] is True
    assert diag["attempted"] is True
    assert diag["reason"] == ""
    assert tr.rstrip().endswith("switch#")


def test_enable_password_uses_the_login_credential_first():
    ch, (tr, diag) = _run(
        "\r\nrouter>",
        [("enable", "\r\nPassword: "), ("s3cret", "\r\nrouter#")],
    )
    assert diag["escalated"] is True
    assert diag["secrets_tried"] == 1
    assert ch.wrote("s3cret\r")


def test_blank_secret_tried_after_the_login_password_is_rejected():
    # The very common case: enable exists, but has no secret of its own.
    ch, (tr, diag) = _run(
        "\r\nsw>",
        [("enable", "\r\nPassword: "),
         ("s3cret", "\r\n% Access denied\r\nPassword: "),
         ("\r", "\r\nsw#")],
    )
    assert diag["escalated"] is True
    assert diag["secrets_tried"] == 2


def test_device_that_re_asks_for_a_username():
    ch, (tr, diag) = _run(
        "\r\nsw>",
        [("enable", "\r\nUsername: "), ("admin", "\r\nPassword: "),
         ("s3cret", "\r\nsw#")],
    )
    assert diag["escalated"] is True
    assert ch.wrote("admin\r")


# ── The two prompts that must be left alone ──────────────────────────────────
def test_never_sends_enable_to_a_unix_shell():
    # "$" and "%" are UNIX shells: `enable` is meaningless there and on some
    # appliances is a real command. This is the regression that matters most.
    for prompt in ("\r\nuser@host:~$ ", "\r\nhost% "):
        ch, (tr, diag) = _run(prompt, [("enable", "\r\nSHOULD NOT HAPPEN")])
        assert ch.wrote("enable") is False
        assert diag["attempted"] is False
        assert diag["escalated"] is False
        assert diag["reason"] == "not_unprivileged"


def test_already_privileged_is_a_noop_but_counts_as_escalated():
    ch, (tr, diag) = _run("\r\nswitch#", [("enable", "\r\nSHOULD NOT HAPPEN")])
    assert ch.wrote("enable") is False
    assert diag["attempted"] is False
    assert diag["escalated"] is True
    assert diag["reason"] == "already_privileged"


def test_login_prompt_is_not_escalated():
    ch, (tr, diag) = _run("\r\nlogin: ", [("enable", "\r\nSHOULD NOT HAPPEN")])
    assert ch.wrote("enable") is False
    assert diag["reason"] == "not_unprivileged"


# ── Refusals: classified, and bounded ────────────────────────────────────────
def test_device_without_an_enable_command():
    # ">" IS the top level here — retrying with another secret is pointless.
    ch, (tr, diag) = _run(
        "\r\nsw>", [("enable", "\r\nInvalid input: enable\r\nsw>")])
    assert diag["attempted"] is True
    assert diag["escalated"] is False
    assert diag["reason"] == "no_enable_support"
    assert diag["secrets_tried"] == 0


def test_wrong_secret_is_reported_as_bad_secret():
    ch, (tr, diag) = _run(
        "\r\nsw>",
        [("enable", "\r\nPassword: "), ("s3cret", "\r\n% Bad secrets\r\nsw>")],
    )
    assert diag["escalated"] is False
    assert diag["reason"] == "bad_secret"
    assert diag["secrets_tried"] == 1


def test_silent_device_gives_up_without_hanging():
    ch, (tr, diag) = _run("\r\nsw>", [])   # `enable` echoes nothing back
    assert diag["attempted"] is True
    assert diag["escalated"] is False
    assert diag["reason"] == "no_prompt"


def test_secrets_are_never_tried_more_than_the_cap():
    # A device that just keeps re-prompting must not be hammered.
    ch, (tr, diag) = _run(
        "\r\nsw>",
        [("enable", "\r\nPassword: ")] + [(s, "\r\nPassword: ")
                                          for s in ("s3cret", "\r")],
    )
    assert diag["escalated"] is False
    assert diag["secrets_tried"] <= fp._ENABLE_ATTEMPTS


def test_no_credentials_still_tries_the_blank_secret():
    ch, (tr, diag) = _run(
        "\r\nsw>", [("enable", "\r\nPassword: "), ("\r", "\r\nsw#")],
        credentials=[], cred_idx=None)
    assert diag["escalated"] is True
    assert diag["secrets_tried"] == 1


def test_dead_line_does_not_raise():
    class _Dead:
        def read(self):
            return b""

        def write(self, b):
            raise OSError("line dropped")

    d = _Dead()
    tr, diag = fp._escalate_privilege(d.read, d.write, [], None, "\r\nsw>")
    assert diag["escalated"] is False


# ── Secret ordering helper ───────────────────────────────────────────────────
def test_enable_secret_order_and_dedup():
    creds = [{"username": "a", "password": "pw1"}]
    assert fp._enable_secrets(creds, 0) == ["pw1", ""]
    # A blank login password must not burn both attempts on the same secret.
    assert fp._enable_secrets([{"username": "a", "password": ""}], 0) == [""]
    # No usable credential index → just the bare Enter.
    assert fp._enable_secrets(creds, None) == [""]
    assert fp._enable_secrets(creds, 5) == [""]
    assert fp._enable_secrets(creds, -1) == [""]
    # A credential dict missing the password key must not raise.
    assert fp._enable_secrets([{"username": "a"}], 0) == [""]


# ── De-escalation of a session we did not authenticate ───────────────────────
def test_deescalate_returns_to_user_mode():
    ch = _Chan("", [("disable", "\r\nsw>")])
    assert fp._deescalate_privilege(ch.read, ch.write) is True
    assert ch.wrote("disable")


def test_deescalate_falls_back_to_exit():
    ch = _Chan("", [("disable", "\r\nInvalid input\r\nsw#"), ("exit", "\r\nsw>")])
    assert fp._deescalate_privilege(ch.read, ch.write) is True
    assert ch.wrote("exit")


def test_deescalate_on_dead_line_is_false_not_an_exception():
    class _Dead:
        def read(self):
            return b""

        def write(self, b):
            raise OSError("gone")

    d = _Dead()
    assert fp._deescalate_privilege(d.read, d.write) is False


# ── End-to-end through run_identify ──────────────────────────────────────────
_IOS_SHOW_VER = (
    "\r\nCisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11\r\n"
    "uptime is 3 weeks\r\nSystem serial number: FOC1234X5YZ\r\nswitch#"
)


def test_run_identify_escalates_before_running_identity_commands():
    """The whole point: log in, land on ">", enable, THEN run the shows."""
    ch = _Chan(
        "\r\nUser Access Verification\r\n\r\nUsername: ",
        [("admin", "\r\nPassword: "),
         ("s3cret", "\r\nswitch>"),
         ("enable", "\r\nPassword: "),
         ("s3cret", "\r\nswitch#"),
         ("show version", _IOS_SHOW_VER)],
    )
    res = fp.run_identify(ch.read, ch.write,
                          [{"username": "admin", "password": "s3cret"}],
                          banner_secs=0.3, cmd_secs=0.3)
    assert res["logged_in"] is True
    en = res["diag"]["enable"]
    assert en["attempted"] is True and en["escalated"] is True
    assert res["diag"]["privilege"] == "enable"
    # `enable` must come AFTER the password and BEFORE any show command.
    order = [s for s in ch.sent if s.strip()]
    i_en = next(i for i, s in enumerate(order) if "enable" in s)
    i_show = next((i for i, s in enumerate(order) if "show" in s), len(order))
    assert i_en < i_show


def test_run_identify_reports_user_mode_when_enable_is_unavailable():
    ch = _Chan(
        "\r\nlogin: ",
        [("admin", "\r\nPassword: "),
         ("s3cret", "\r\nsw>"),
         ("enable", "\r\nInvalid input\r\nsw>")],
    )
    res = fp.run_identify(ch.read, ch.write,
                          [{"username": "admin", "password": "s3cret"}],
                          banner_secs=0.3, cmd_secs=0.3)
    d = res["diag"]
    assert d["enable"]["reason"] == "no_enable_support"
    assert d["privilege"] == "user"
    assert "no `enable` command" in d["enable_reason"]
