"""Regression: the spoke-reconnect config projection must carry ``verify_ssl``.

There are TWO code paths that project a stored NAC/IPAM instance into the
``UPDATE_CONFIG`` payload sent to a spoke:

* the **Save** path — ``routes.tenant_devices._NAC_PAYLOAD`` / ``_IPAM_PAYLOAD``
  (runs when the operator saves the instance form); and
* the **reconnect** path — ``main._INSTANCE_CONFIG_SOURCES`` (runs from
  ``push_config_to_spoke`` on every spoke (re)connect, e.g. the hourly
  self-update restart).

These MUST stay in sync. A prior bug dropped ``verify_ssl`` from the reconnect
projection only: saving a self-signed ClearPass with "allow untrusted" worked
immediately, but the very next spoke restart re-pushed a config WITHOUT
``verify_ssl`` — and because the spoke reconstructs its client at the secure
default (``verify=True``) on restart, TLS verification silently switched back on
and every ``/api/session`` query failed ``CERTIFICATE_VERIFY_FAILED``.
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
    assert out["verify_ssl"] is True  # secure default, mirrors _NAC_PAYLOAD


def test_cppm_reconnect_projection_matches_nac_payload_keys():
    from routes.tenant_devices import _NAC_PAYLOAD
    rec = {"host": "h", "client_id": "c", "client_secret": "s",
           "user": "u", "password": "p", "verify_ssl": False}
    assert set(_project("cppm", rec)) == set(_NAC_PAYLOAD(rec))


def test_netbox_reconnect_projection_forwards_verify_ssl():
    out = _project("netbox", {"netbox_url": "https://nb", "api_token": "t",
                              "verify_ssl": False})
    assert out["netbox_verify_ssl"] is False
