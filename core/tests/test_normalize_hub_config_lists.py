"""``normalize_hub_config_lists`` — the Setup/Proxmox list fields are collected
in the WebUI as comma/space-delimited text (no raw JSON) and normalized to lists
on the hub before ``store.set_hub_config`` + ``_push_config``. Downstream
(``cs spoke _parse_json_list`` / pxmx agent) expects a list.

Pins: delimited → list (comma AND whitespace); already-list / already-JSON
passthrough; dedup + lowercase for vidpid fields; invalid vidpids dropped;
``ignored_hostnames`` keeps arbitrary strings + order; ``usb_vidpids`` →
``{vidpid,type,label}`` dicts with type/label preserved from the stored entry.
"""
import json

from simulations.routes import normalize_hub_config_lists


# ── string-list fields ───────────────────────────────────────────────────────

def test_delimited_comma_to_list():
    out = normalize_hub_config_lists({"usb_ignored_vidpids": "1a2b:3c4d, 5678:9abc"})
    assert out["usb_ignored_vidpids"] == ["1a2b:3c4d", "5678:9abc"]


def test_delimited_whitespace_to_list():
    out = normalize_hub_config_lists({"t1_pci_vidpids": "1912:0015 168c:0034"})
    assert out["t1_pci_vidpids"] == ["1912:0015", "168c:0034"]


def test_mixed_comma_and_whitespace():
    out = normalize_hub_config_lists({"t3_pci_vidpids": "168c:0034,  abcd:ef01 1111:2222"})
    assert sorted(out["t3_pci_vidpids"]) == ["1111:2222", "168c:0034", "abcd:ef01"]


def test_already_list_passthrough_dedup_lowercases():
    out = normalize_hub_config_lists({"usb_ignored_vidpids": ["1A2B:3C4D", "1a2b:3c4d", "x"]})
    # deduped (case-insensitive) + invalid "x" dropped
    assert out["usb_ignored_vidpids"] == ["1a2b:3c4d"]


def test_already_json_string_passthrough():
    out = normalize_hub_config_lists({"usb_ignored_vidpids": '["1a2b:3c4d"]'})
    assert out["usb_ignored_vidpids"] == ["1a2b:3c4d"]


def test_empty_string_to_empty_list():
    out = normalize_hub_config_lists({"usb_ignored_vidpids": ""})
    assert out["usb_ignored_vidpids"] == []


def test_ignored_hostnames_keeps_arbitrary_strings_and_order():
    # Hostnames never contain spaces, so space-delimited splitting is safe.
    out = normalize_hub_config_lists({"ignored_hostnames": "sim-rpi-0000, sim-rpi-0001, sim-rpi-0000"})
    # deduped, order preserved
    assert out["ignored_hostnames"] == ["sim-rpi-0000", "sim-rpi-0001"]


# ── usb_vidpids (object list) ────────────────────────────────────────────────

def test_usb_vidpids_delimited_to_objects():
    out = normalize_hub_config_lists({"usb_vidpids": "1a2b:3c4d, 5678:9abc"})
    assert out["usb_vidpids"] == [
        {"vidpid": "1a2b:3c4d", "type": "wireless", "label": "1a2b:3c4d"},
        {"vidpid": "5678:9abc", "type": "wireless", "label": "5678:9abc"},
    ]


def test_usb_vidpids_preserves_type_label_from_stored():
    stored = {"usb_vidpids": [{"vidpid": "1a2b:3c4d", "type": "wired", "label": "My Dongle"}]}
    out = normalize_hub_config_lists({"usb_vidpids": "1a2b:3c4d, 9999:8888"}, stored)
    assert out["usb_vidpids"] == [
        {"vidpid": "1a2b:3c4d", "type": "wired", "label": "My Dongle"},   # preserved
        {"vidpid": "9999:8888", "type": "wireless", "label": "9999:8888"},  # defaulted
    ]


def test_usb_vidpids_already_objects_passthrough_dedup():
    raw = [{"vidpid": "1a2b:3c4d", "type": "wired", "label": "x"}, {"vidpid": "1A2B:3C4D"}]
    out = normalize_hub_config_lists({"usb_vidpids": raw})
    assert [d["vidpid"] for d in out["usb_vidpids"]] == ["1a2b:3c4d"]
    assert out["usb_vidpids"][0]["type"] == "wired"   # preserved


def test_usb_vidpids_drops_invalid():
    out = normalize_hub_config_lists({"usb_vidpids": "1a2b:3c4d, nope, 5678:9abc"})
    assert [d["vidpid"] for d in out["usb_vidpids"]] == ["1a2b:3c4d", "5678:9abc"]


# ── invariants ───────────────────────────────────────────────────────────────

def test_fields_not_present_left_untouched():
    out = normalize_hub_config_lists({"usb_auto_provision": "on", "vmid_start": 90000})
    assert out == {"usb_auto_provision": "on", "vmid_start": 90000}


def test_does_not_mutate_caller_dict():
    src = {"usb_ignored_vidpids": "1a2b:3c4d"}
    normalize_hub_config_lists(src)
    assert src == {"usb_ignored_vidpids": "1a2b:3c4d"}   # unchanged


def test_non_dict_passes_through():
    assert normalize_hub_config_lists(None) is None
    assert normalize_hub_config_lists("x") == "x"


def test_full_round_trip_matches_downstream_parse():
    # After normalization, json.dumps(value) is what's stored/pushed; the cs
    # spoke _parse_json_list must read it back as a list.
    out = normalize_hub_config_lists({"usb_vidpids": "1a2b:3c4d, 5678:9abc",
                                      "usb_ignored_vidpids": "dead:beef"})
    assert isinstance(json.loads(json.dumps(out["usb_vidpids"])), list)
    assert isinstance(json.loads(json.dumps(out["usb_ignored_vidpids"])), list)