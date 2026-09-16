"""A tenant user could not edit their OWN NetBox objects: 403, every time.

    Error: 403 Object not found in your tenant (cross-tenant mutation denied)

``_verify_owns`` is the cross-tenant gate on the eight NetBox path-ID mutation
routes (PUT/DELETE of racks, devices, prefixes, IPs). It answered "is this id
in the caller's tenant cache?" like this::

    cached = _cache_entry(tid, module_key)
    if cached and _in(cached.get("data")):        # _in iterates `items`

but the tenant cache does not hold a bare row list. ``_fetch_module`` stores
the spoke's REPLY ENVELOPE, and the NetBox list replies are shaped::

    {"status": "SUCCESS", "prefixes": [...]}      # netbox_ipam.py:45
    {"status": "SUCCESS", "ip_addresses": [...]}  # netbox_ipam.py:347
    {"status": "SUCCESS", "devices": [...]}       # netbox_dcim.py:85
    {"status": "SUCCESS", "racks": [...]}         # netbox_dcim.py:56

``_normalize_cached`` only unwraps a ``"data"``/``"payload"`` key and these
have neither, so it passes the envelope through untouched. Iterating a dict
yields its KEYS, so ``_in`` compared the strings ``"status"`` and ``"prefixes"``
against the object id, ``isinstance(it, dict)`` was False for both, and the
answer was ALWAYS False -- for the live refresh too. Every non-admin PUT/DELETE
was dead, including "edit a prefix description" and "enable DHCP on a subnet",
which both go through ``PUT /api/netbox/prefixes/{id}``.

The reason this survived is in the tests: the existing cases seed
``{"data": [{"id": 5}]}`` -- an already-unwrapped list that ``_fetch_module``
never writes -- so the gate passed in tests and failed in production. The cases
below use the REAL envelope, and the "not owned" cases are re-asserted against
it so the fix cannot be mistaken for simply opening the gate.
"""

import pytest

import api as api_mod

from test_auth_session_security import (  # noqa: F401  (fixtures)
    _build, _mint_session, _mint_tenant_session, _isolate,
)


def _envelope(key, rows):
    """Exactly what _fetch_module stores for a NetBox list module."""
    return {"data": {"status": "SUCCESS", key: rows}}


# --- the reported symptom -------------------------------------------------

def test_a_tenant_user_can_edit_a_prefix_in_their_own_tenant(tmp_path):
    c, hub = _build({}, tmp_path)
    api_mod._tenant_cache["tA"] = {
        "netbox_prefixes": _envelope("prefixes", [{"id": 42, "prefix": "172.17.1.0/24"}])}
    tok = _mint_tenant_session(hub, "lrb", "tA", rights=("ipam", "edit"))
    r = c.put("/api/netbox/prefixes/42", json={"description": "renamed"},
              cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    assert "cross-tenant mutation denied" not in r.text


def test_a_tenant_user_can_enable_dhcp_on_their_own_subnet(tmp_path):
    # Same route as the description edit -- the WebUI's "enable DHCP" checkbox
    # is a custom_fields PUT on the prefix.
    c, hub = _build({}, tmp_path)
    api_mod._tenant_cache["tA"] = {
        "netbox_prefixes": _envelope("prefixes", [{"id": 42}])}
    tok = _mint_tenant_session(hub, "lrb", "tA", rights=("ipam", "edit"))
    r = c.put("/api/netbox/prefixes/42",
              json={"description": "lab", "status": "active",
                    "custom_fields": {"dhcp_enabled": True}},
              cookies={"lm_session": tok})
    assert r.status_code == 200, r.text


@pytest.mark.parametrize("module_key,row_key,path", [
    ("netbox_prefixes", "prefixes", "/api/netbox/prefixes/42"),
    ("netbox_devices", "devices", "/api/netbox/devices/42"),
    ("netbox_ips", "ip_addresses", "/api/netbox/ips/42"),
])
def test_every_guarded_module_accepts_its_real_cache_shape(
        tmp_path, module_key, row_key, path):
    c, hub = _build({}, tmp_path)
    api_mod._tenant_cache["tA"] = {module_key: _envelope(row_key, [{"id": 42}])}
    tok = _mint_tenant_session(hub, "lrb", "tA", rights=("ipam", "edit"))
    r = c.delete(path, cookies={"lm_session": tok})
    assert r.status_code == 200, f"{module_key}: {r.text}"


# --- the gate still closes -----------------------------------------------

@pytest.mark.parametrize("module_key,row_key,path", [
    ("netbox_prefixes", "prefixes", "/api/netbox/prefixes/999"),
    ("netbox_devices", "devices", "/api/netbox/devices/999"),
    ("netbox_ips", "ip_addresses", "/api/netbox/ips/999"),
])
def test_another_tenants_object_is_still_denied(tmp_path, module_key, row_key, path):
    # The whole point of the gate: id enumeration must stay fail-closed. These
    # use the REAL shape too, so a "fix" that just stopped denying would fail.
    c, hub = _build({}, tmp_path)
    api_mod._tenant_cache["tA"] = {module_key: _envelope(row_key, [{"id": 42}])}
    tok = _mint_tenant_session(hub, "lrb", "tA", rights=("ipam", "edit"))
    r = c.delete(path, cookies={"lm_session": tok})
    assert r.status_code == 403
    assert "cross-tenant mutation denied" in r.text


def test_an_empty_tenant_list_denies_everything(tmp_path):
    c, hub = _build({}, tmp_path)
    api_mod._tenant_cache["tA"] = {"netbox_prefixes": _envelope("prefixes", [])}
    tok = _mint_tenant_session(hub, "lrb", "tA", rights=("ipam", "edit"))
    r = c.put("/api/netbox/prefixes/42", json={"description": "x"},
              cookies={"lm_session": tok})
    assert r.status_code == 403


def test_a_cache_holding_another_modules_rows_does_not_authorise(tmp_path):
    # prefixes cache keyed under "devices": the row key must be matched, not
    # "any list in the envelope". Guessing here would authorise a mutation.
    c, hub = _build({}, tmp_path)
    api_mod._tenant_cache["tA"] = {"netbox_prefixes": _envelope("devices", [{"id": 42}])}
    tok = _mint_tenant_session(hub, "lrb", "tA", rights=("ipam", "edit"))
    r = c.put("/api/netbox/prefixes/42", json={"description": "x"},
              cookies={"lm_session": tok})
    assert r.status_code == 403


def test_an_unrecognised_cache_shape_fails_closed(tmp_path):
    c, hub = _build({}, tmp_path)
    api_mod._tenant_cache["tA"] = {"netbox_prefixes": {"data": "not-a-container"}}
    tok = _mint_tenant_session(hub, "lrb", "tA", rights=("ipam", "edit"))
    r = c.put("/api/netbox/prefixes/42", json={"description": "x"},
              cookies={"lm_session": tok})
    assert r.status_code == 403


def test_one_tenants_cache_never_authorises_another_tenants_user(tmp_path):
    c, hub = _build({}, tmp_path)
    api_mod._tenant_cache["tB"] = {
        "netbox_prefixes": _envelope("prefixes", [{"id": 42}])}
    tok = _mint_tenant_session(hub, "lrb", "tA", rights=("ipam", "edit"))
    r = c.put("/api/netbox/prefixes/42", json={"description": "x"},
              cookies={"lm_session": tok})
    assert r.status_code == 403


# --- shapes that must keep working ---------------------------------------

def test_the_already_unwrapped_list_shape_still_works(tmp_path):
    # _normalize_cached DOES unwrap a "data" key, so a spoke/proxied shard that
    # hands back a bare list must keep passing. Dropping this would break the
    # proxied-tenant shard path.
    c, hub = _build({}, tmp_path)
    api_mod._tenant_cache["tA"] = {"netbox_devices": {"data": [{"id": 5}]}}
    tok = _mint_tenant_session(hub, "lrb", "tA", rights=("ipam", "edit"))
    r = c.delete("/api/netbox/devices/5", cookies={"lm_session": tok})
    assert r.status_code == 200


def test_an_admin_still_bypasses_the_gate_entirely(tmp_path):
    c, hub = _build({}, tmp_path)
    r = c.delete("/api/netbox/devices/999",
                 cookies={"lm_session": _mint_session(hub, "admin")})
    assert r.status_code == 200


def test_a_string_id_in_the_cache_matches_an_integer_path_id(tmp_path):
    # NetBox ids arrive as ints, but a shard round-trip can stringify them.
    c, hub = _build({}, tmp_path)
    api_mod._tenant_cache["tA"] = {
        "netbox_prefixes": _envelope("prefixes", [{"id": "42"}])}
    tok = _mint_tenant_session(hub, "lrb", "tA", rights=("ipam", "edit"))
    r = c.put("/api/netbox/prefixes/42", json={"description": "x"},
              cookies={"lm_session": tok})
    assert r.status_code == 200
