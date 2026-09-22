"""Partial-string global search: list-aware blob, IP-query detection, and the
cold-leg selection that keeps NetBox from being hidden by a memory hit."""
import search_index as si


# ── search_result_blob: list members ───────────────────────────────────────────
def test_blob_includes_list_members():
    item = {"name": "sw1", "macs": ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"],
            "tags": ["core", "edge"]}
    for needle in ("ee:ff", "11:22", "edge"):
        assert si.search_result_matches(item, needle)


def test_blob_ignores_dicts_bools_none_and_nested():
    item = {"a": {"secret": "hidden-dict"}, "b": True, "c": None,
            "d": [["nested-list"], {"k": "list-dict"}, None, True, "ok-member"],
            "e": ("tuple-member",)}
    blob = si.search_result_blob(item)
    assert "hidden-dict" not in blob
    assert "nested-list" not in blob
    assert "list-dict" not in blob
    assert "true" not in blob and "none" not in blob
    assert "ok-member" in blob
    assert "tuple-member" in blob


def test_blob_list_cap_and_field_length():
    item = {"ids": ["m%d" % i for i in range(60)]}
    blob = si.search_result_blob(item)
    assert "m49" in blob
    assert "m50" not in blob
    big = "x" * (si._MAX_BLOB_FIELD + 1)
    ok = "y" * si._MAX_BLOB_FIELD
    blob = si.search_result_blob({"l": [big, ok, ""], "s": big})
    assert big not in blob
    assert ok in blob


# ── search_result_matches: realistic partials ──────────────────────────────────
def test_matches_partial_device_fields():
    assert si.search_result_matches(
        {"name": "sw1", "device_type": "Catalyst C9300-48P"}, "c9300")
    assert si.search_result_matches({"name": "sw-MIAmi-01"}, "miam")
    assert si.search_result_matches({"ip": "10.20.30.40/24"}, "20.30")
    assert si.search_result_matches(
        {"source": "SEARCH_DHCP", "mac": "aa:bb:cc:dd:ee:ff"}, "bb:cc")
    assert not si.search_result_matches({"name": "sw1"}, "zzz")


# ── is_ip_query ────────────────────────────────────────────────────────────────
def test_is_ip_query_true():
    for q in ("10.20.0.5", "10.20", "10.0.0.0/24", "2001:db8::1", "::1",
              " 10.1.2.3 ", "2001:0db8:0000:0000:0000:0000:0000:0001", "fe80::1/64"):
        assert si.is_ip_query(q), q


def test_is_ip_query_false():
    for q in ("ks205", "12345", "", "aa:bb:cc:dd:ee:ff", "MIAm", "1.2.3.x",
              "abc.def"):
        assert not si.is_ip_query(q), q


# ── cold_live_legs ─────────────────────────────────────────────────────────────
_LEGS = [("nb", "NETBOX_SEARCH"), ("hv", "SEARCH_VMS"),
         (None, "SEARCH_SESSIONS"), ("ld", "SEARCH_USERS"),
         ("fw", "SEARCH_DHCP")]


def test_cold_live_legs_selects_cold_with_spoke_excluding_dhcp():
    warm = {"NETBOX_SEARCH": None, "SEARCH_VMS": [{"name": "x"}],
            "SEARCH_SESSIONS": None, "SEARCH_USERS": None, "SEARCH_DHCP": None}
    assert si.cold_live_legs(_LEGS, warm) == [
        ("nb", "NETBOX_SEARCH"), ("ld", "SEARCH_USERS")]


def test_cold_live_legs_missing_key_is_cold():
    # An empty-but-present list is warm; an absent key is cold.
    assert si.cold_live_legs(_LEGS, {"SEARCH_VMS": []}) == [
        ("nb", "NETBOX_SEARCH"), ("ld", "SEARCH_USERS")]


def test_cold_live_legs_all_warm_returns_empty():
    warm = {cmd: [] for _s, cmd in _LEGS}
    assert si.cold_live_legs(_LEGS, warm) == []
