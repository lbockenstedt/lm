"""Regression: the spoke config projection must carry ``verify_ssl``.

``main._INSTANCE_CONFIG_SOURCES`` projects a stored NAC/IPAM instance into the
``UPDATE_CONFIG`` payload sent to a spoke. For NAC it is the only projection:
every Setup → NAC save, move and delete, the tenant-admin device routes and
every spoke (re)connect send it through ``LabManagerHub.push_nac_config``.

A prior bug dropped ``verify_ssl`` from the reconnect projection only: saving a
self-signed ClearPass with "allow untrusted" worked immediately, but the very
next spoke restart re-pushed a config WITHOUT ``verify_ssl`` — and because the
spoke reconstructs its client at the secure default (``verify=True``) on
restart, TLS verification silently switched back on and every
``/api/session`` query failed ``CERTIFICATE_VERIFY_FAILED``.
"""
import main


def _project(module_key, record):
    _storage_key, project = main._INSTANCE_CONFIG_SOURCES[module_key]
    return project(record)


def test_cppm_reconnect_projection_forwards_verify_ssl_false():
    out = _project("cppm", {
        "host": "172.16.1.16", "client_id": "c", "client_secret": "s",
        "user": "u", "password": "p", "verify_ssl": False,
    })
    assert out["verify_ssl"] is False, \
        "reconnect push must carry verify_ssl=False or TLS verify re-enables on restart"


def test_cppm_reconnect_projection_defaults_verify_ssl_true_when_absent():
    out = _project("cppm", {"host": "172.16.1.16"})
    assert out["verify_ssl"] is True  # secure default


def test_cppm_projection_carries_every_connection_field():
    rec = {"host": "h", "client_id": "c", "client_secret": "s",
           "user": "u", "password": "p", "verify_ssl": False}
    assert set(_project("cppm", rec)) == {
        "host", "client_id", "client_secret", "user", "password", "verify_ssl"}


def test_netbox_reconnect_projection_forwards_verify_ssl():
    out = _project("netbox", {"netbox_url": "https://nb", "api_token": "t",
                              "verify_ssl": False})
    assert out["netbox_verify_ssl"] is False


# ── string-valued verify_ssl coercion (bool("false") is True trap) ───────────
# verify_ssl can be persisted as a STRING ("false"/"0") — older UI, hand-edited
# config, or a stringifying relay. The projection must coerce to a real bool
# so a truthy string can't be pushed and re-enable TLS verify on the spoke.
def test_cppm_reconnect_projection_coerces_string_false():
    for falsey in ("false", "False", "0", "no", "off"):
        out = _project("cppm", {"host": "172.16.1.16", "verify_ssl": falsey})
        assert out["verify_ssl"] is False, f"{falsey!r} must project to False"


def test_cppm_reconnect_projection_coerces_string_true():
    out = _project("cppm", {"host": "172.16.1.16", "verify_ssl": "true"})
    assert out["verify_ssl"] is True
