"""VSF stack detection for the Console role.

Every sample here is VERBATIM console output captured from the live fleet (or,
where noted, from HPE's published command reference) rather than hand-written —
the column layouts are space-aligned, vary by firmware, and a plausible-looking
invented sample would not have caught the real quirks these pin down:

* the AOS-CX header wraps ("Mbr Mac Address type Status" then a bare "ID"),
* a standby member prints a REDUCED table with no header block at all and names
  itself via "This Mbr ID",
* a standby's CLI prompt is the bare word "standby",
* AOS-S says "Commander" where AOS-CX says "Conductor",
* a long AOS-S model name runs straight into the priority column with no space.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from vsf_stack import (  # noqa: E402
    at_standby_console,
    normalize_member_mac,
    parse_show_version,
    parse_show_vsf,
)

# --- verbatim captures ------------------------------------------------------

# Conductor port of a live 2-member AOS-CX 6300 stack (BO-SYDm-ACSW01).
CX_CONDUCTOR = """BO-SYDm-ACSW01# show vsf

Force Autojoin             : Disabled
Autojoin Eligibility Status: Not Eligible
MAC Address                : 8c:85:c1:4b:c7:80
Egress Shape               : Enabled
Egress Shape Rate          : None
Secondary                  : 2
Topology                   : Ring
Status                     : No Split
Split Detection Method     : mgmt


Mbr Mac Address         type           Status
ID
--- ------------------- -------------- ---------------
1   8c:85:c1:4b:c7:80   JL662A         Conductor
2   34:c5:15:9b:52:00   JL666A         Standby
BO-SYDm-ACSW01# """

# The same chassis BEFORE the stack was formed.
CX_STANDALONE = """6300# show vsf

Force Autojoin             : Disabled
Autojoin Eligibility Status: Eligible
MAC Address                : 8c:85:c1:4b:c7:80
Topology                   : Standalone
Status                     : No Split
Split Detection Method     : None


Mbr Mac Address         type           Status
ID
--- ------------------- -------------- ---------------
1   8c:85:c1:4b:c7:80   JL662A         Conductor
6300# """

# The standby member's console on the same stack: reduced output, no header.
CX_STANDBY = """standby# show vsf

This Mbr ID              : 2

Mbr Mac Address         type           Status
ID
--- ------------------- -------------- ---------------
1   8c:85:c1:4b:c7:80   JL662A         Conductor
2   34:c5:15:9b:52:00   JL666A         Standby
standby# """

CX_STANDBY_LOGIN = """6300 login: admin

Password:
standby#
standby# """

CX_VERSION = """standby# show version
-----------------------------------------------------------------------------
AOS-CX
(c) Copyright 2017-2026 Hewlett Packard Enterprise Development LP
-----------------------------------------------------------------------------
Version      : FL.10.13.1000
Build Date   : 2024-05-30 02:23:13 PDT
Active Image : primary

Service OS Version : FL.01.19.0002
BIOS Version       : FL.01.0016
standby# """

# AOS-S / ProCurve 2930F VSF (HPE command reference).
AOSS_VSF = """switch# show vsf

VSF Domain ID : 123
MAC Address   : 941882-435589
VSF Topology  : Ring
VSF Status    : Active
Uptime        : 26d 20h 36m
VSF MAD       : None
VSF Port Speed: 10G
Software Version : WC.16.06.0000x

Mbr ID  MAC Address       Model                            Pri  Status
-----   ----------------  -----------------------------    ---  ---------------
1       f40343-0796b0     Aruba JL258A 2930F-8G-PoE+-2SFP+ 128  Member
*2      941882-435580     Aruba JL254A 2930F-48G-4SFP+     128  Commander
3       b05ada-9771c0     Aruba JL256A 2930F-48G-PoE+-4SFP+128  Standby
switch# """

# Newer AOS-CX firmware: a separate Role column plus an empty (Not Present) slot.
CX_ROLE_COLUMN = """switch# show vsf

MAC Address              : 08:97:34:b0:0e:00
Topology                 : Chain
Status                   : Active Fragment

 Mbr   MAC Address         Type      Status           Role
---------------------------------------------------------------
  1    08:97:34:b0:0e:00   JL666A    Conductor        Conductor
  2    08:97:34:b1:43:00   JL665A    In Other Frag    Standby
  3    08:97:34:b7:cc:00   S0E91A    Member           Member
  4    JL662A              Not Present
switch# """


# --- MAC normalization ------------------------------------------------------

@pytest.mark.parametrize("raw,want", [
    ("8c:85:c1:4b:c7:80", "8c:85:c1:4b:c7:80"),   # AOS-CX
    ("941882-435589", "94:18:82:43:55:89"),       # AOS-S
    ("8c85.c14b.c780", "8c:85:c1:4b:c7:80"),      # dotted
    ("8C85C14BC780", "8c:85:c1:4b:c7:80"),        # bare, upper
])
def test_mac_forms_collapse_to_one_spelling(raw, want):
    """Cross-referencing a stack member against a port is a string compare, so
    every firmware's MAC notation has to reduce to the same text."""
    assert normalize_member_mac(raw) == want


@pytest.mark.parametrize("raw", ["JL662A", "", "Not Present", "8c:85:c1:4b:c7"])
def test_non_macs_are_rejected(raw):
    """An empty stack slot puts the MODEL in the MAC column — it must not be
    mistaken for an address and indexed as one."""
    assert normalize_member_mac(raw) == ""


# --- show vsf ---------------------------------------------------------------

def test_conductor_row_is_identified_as_local():
    """AOS-CX prints the local chassis' own MAC in the header, which is how we
    know which member we are attached to when there is no "*" marker."""
    r = parse_show_vsf(CX_CONDUCTOR)
    assert r["is_stack"] is True
    assert r["topology"] == "Ring"
    assert r["stack_mac"] == "8c:85:c1:4b:c7:80"
    assert r["local_member_id"] == 1
    assert r["local_role"] == "conductor"
    assert r["members"] == [
        {"member_id": 1, "mac": "8c:85:c1:4b:c7:80", "model": "JL662A",
         "role": "conductor", "present": True},
        {"member_id": 2, "mac": "34:c5:15:9b:52:00", "model": "JL666A",
         "role": "standby", "present": True},
    ]


def test_standalone_switch_is_not_a_stack():
    """A lone switch still reports itself as "Conductor" of a 1-member VSF — it
    must not light up the stack UI."""
    r = parse_show_vsf(CX_STANDALONE)
    assert r["is_stack"] is False
    assert r["topology"] == "Standalone"
    assert r["local_role"] == "conductor"
    assert len(r["members"]) == 1


def test_standby_reduced_output_still_locates_itself():
    """The standby's table has no header block, so "This Mbr ID" is the only
    thing that says which member we're on — and it must win."""
    r = parse_show_vsf(CX_STANDBY)
    assert r["is_stack"] is True
    assert r["stack_mac"] == ""       # no header MAC line in this form
    assert r["topology"] == ""
    assert r["local_member_id"] == 2
    assert r["local_role"] == "standby"
    assert [m["mac"] for m in r["members"]] == [
        "8c:85:c1:4b:c7:80", "34:c5:15:9b:52:00"]


def test_standby_sees_the_conductor_mac():
    """This is the whole cross-reference: the standby's own output names the
    conductor's MAC, which the hub matches to another console port."""
    r = parse_show_vsf(CX_STANDBY)
    conductors = [m["mac"] for m in r["members"] if m["role"] == "conductor"]
    assert conductors == ["8c:85:c1:4b:c7:80"]


def test_aoss_commander_is_the_same_role_as_conductor():
    """AOS-S and AOS-CX use different words for the same thing; the UI must not
    have to know which firmware it is looking at."""
    r = parse_show_vsf(AOSS_VSF)
    assert r["topology"] == "Ring"
    assert r["stack_mac"] == "94:18:82:43:55:89"
    assert r["local_member_id"] == 2       # from the "*" marker
    assert r["local_role"] == "conductor"  # printed as "Commander"
    assert [m["role"] for m in r["members"]] == ["member", "conductor", "standby"]


def test_aoss_model_is_split_from_the_glued_priority_column():
    """Row 3's model runs straight into the Pri column ("...4SFP+128") because
    the table is space-aligned, not delimited."""
    r = parse_show_vsf(AOSS_VSF)
    assert [m["model"] for m in r["members"]] == [
        "Aruba JL258A 2930F-8G-PoE+-2SFP+",
        "Aruba JL254A 2930F-48G-4SFP+",
        "Aruba JL256A 2930F-48G-PoE+-4SFP+",
    ]


def test_role_column_firmware_and_empty_slots():
    """Newer firmware repeats the role in a Status AND a Role column, and lists
    unpopulated slots whose MAC column holds a model instead."""
    r = parse_show_vsf(CX_ROLE_COLUMN)
    assert r["topology"] == "Chain"
    assert r["local_member_id"] == 1
    assert r["members"][-1] == {"member_id": 4, "mac": "", "model": "JL662A",
                                "role": "", "present": False}
    assert [m["model"] for m in r["members"][:3]] == ["JL666A", "JL665A", "S0E91A"]
    assert [m["role"] for m in r["members"][:3]] == ["conductor", "standby", "member"]


@pytest.mark.parametrize("junk", [
    "", "Invalid input: vsf", "\x00\xff\x1b[2J garbage",
    "Mbr ID\n--- ---\n", "show vsf\n  <cr>\n",
])
def test_garbage_never_raises_and_claims_nothing(junk):
    """This is fed raw serial text — a CLI rejection or line noise must produce
    an empty record, never an exception inside a probe."""
    r = parse_show_vsf(junk)
    assert r["is_stack"] is False
    assert r["members"] == []
    assert r["local_member_id"] is None


# --- show version -----------------------------------------------------------

def test_image_version_is_not_the_service_os_or_bios_version():
    """AOS-CX prints three different "Version" lines; only the bare one is the
    switch image an operator compares across stack members."""
    assert parse_show_version(CX_VERSION) == "FL.10.13.1000"


def test_aoss_software_version_label():
    assert parse_show_version(AOSS_VSF) == "WC.16.06.0000x"


def test_aoss_image_stamp_token():
    """Older AOS-S prints the version as a bare token under "Image stamp:"."""
    text = ("Image stamp:    /ws/swbuildm/rel_ukiah_qaoff/code/build/bom(*)\n"
            "                Apr 12 2023 07:49:52\n"
            "                WC.16.10.0021\n")
    assert parse_show_version(text) == "WC.16.10.0021"


def test_unknown_version_is_empty_not_a_guess():
    assert parse_show_version("nothing to see here") == ""


# --- standby console detection ---------------------------------------------

@pytest.mark.parametrize("text", [
    CX_STANDBY_LOGIN,                # verbatim live capture
    "standby# ",
    "standby> ",
    "myswitch-standby login: ",
    "(standby) login: ",
    "This is the standby member of the VSF stack\n",
])
def test_standby_console_is_recognized(text):
    """The trigger for the whole feature: without this the port stays an
    unidentifiable box, because a standby rejects the identity commands."""
    assert at_standby_console(text) is True


@pytest.mark.parametrize("text", [
    "",
    "BO-SYDm-ACSW01 login: ",
    "BO-SYDm-ACSW01# ",
    "6300 login: ",
    CX_CONDUCTOR,   # contains the word "Standby" in a member row
])
def test_ordinary_consoles_are_not_mistaken_for_a_standby(text):
    """A `show vsf` table legitimately contains the word "Standby"; only the
    prompt we are actually sitting at counts."""
    assert at_standby_console(text) is False


def test_only_the_tail_is_considered():
    """A standby prompt scrolled far up the capture is history, not where we are
    now — otherwise a port would stay flagged forever after one visit."""
    assert at_standby_console("standby#\n" + ("x" * 1000) + "\nrouter# ") is False
