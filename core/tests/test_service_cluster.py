"""Coordinator/worker service-cluster transport tests.

Two things must hold for a clustered dns/dhcp module to be trustworthy:

1. **The command surface is closed.** The coordinator can only issue commands
   from the allowlist it was constructed with, and a worker can only execute ops
   in its fixed table. Neither takes a command name from a request.
2. **A partial fan-out is never reported as success.** ``fanout`` returns
   ``PARTIAL`` the moment one member fails or is offline.

The last test is the real proof: a live ``AgentHostingControlPlane`` listener on
loopback with TWO authenticated ``ServiceWorkerClient``s dialing it, driven end
to end through ``send_to_agent``.
"""

import asyncio
import os
import ssl

import pytest

from messaging.agent_hosting import AgentHostingControlPlane, ListenerRequiresTLS
from messaging.service_cluster import (
    CLUSTER_PORTS, ClusterCoordinator, InsecureCoordinatorURL,
    ServiceWorkerClient, cluster_client_ssl_context, normalize_coordinator_url,
    normalize_members,
)


# ── normalize_members ───────────────────────────────────────────────────────

def test_normalize_members_accepts_strings_and_dicts():
    got = normalize_members(["a", {"id": "b", "host": "10.0.0.2", "role": "Primary"}])
    assert got == [{"id": "a", "host": "", "role": ""},
                   {"id": "b", "host": "10.0.0.2", "role": "primary"}]


def test_normalize_members_drops_unusable_and_dedupes():
    got = normalize_members([{"host": "10.0.0.1"}, "a", {"id": "a"}, 7, None])
    assert [m["id"] for m in got] == ["a"]


# ── ClusterCoordinator ──────────────────────────────────────────────────────

class FakePlane:
    """Minimal stand-in for AgentHostingControlPlane's fan-out surface."""

    def __init__(self, connected, replies=None, fail=()):
        self.connected_agents = {
            cid: {"ws": object(), "last_seen": 1000.0, "version": "1.0"}
            for cid in connected}
        self.pending_agents = {}
        self.replies = replies or {}
        self.fail = set(fail)
        self.sent = []

    async def send_to_agent(self, cmd, data, agent_id=None, timeout=15.0):
        self.sent.append((agent_id, cmd, data))
        if agent_id in self.fail:
            raise RuntimeError("boom")
        return self.replies.get((agent_id, cmd), {"status": "SUCCESS"})


def _coord(plane, members=("a", "b"), allowed=("OP_ONE", "OP_TWO")):
    return ClusterCoordinator("dns", allowed, lambda: plane, members=members)


def test_enabled_requires_two_members():
    plane = FakePlane(["a"])
    assert _coord(plane, members=["a"]).enabled is False
    assert _coord(plane, members=["a", "b"]).enabled is True


async def test_call_refuses_a_command_outside_the_allowlist():
    plane = FakePlane(["a", "b"])
    coord = _coord(plane)
    with pytest.raises(ValueError, match="not allowed"):
        await coord.call("a", "RUN_COMMAND", {"command": "rm -rf /"})
    with pytest.raises(ValueError, match="not allowed"):
        await coord.fanout("WRITE_FILE", {"path": "/etc/shadow"})
    assert plane.sent == []


async def test_call_on_a_disconnected_member_is_an_error_not_an_exception():
    plane = FakePlane(["a"])
    reply = await _coord(plane).call("b", "OP_ONE", {})
    assert reply["status"] == "ERROR"
    assert "not connected" in reply["message"]


async def test_fanout_all_ok_is_success():
    plane = FakePlane(["a", "b"])
    result = await _coord(plane).fanout("OP_ONE", {"x": 1})
    assert result["status"] == "SUCCESS"
    assert sorted(result["ok"]) == ["a", "b"] and result["failed"] == []


async def test_fanout_reports_partial_when_one_member_is_offline():
    plane = FakePlane(["a"])                       # b never connected
    result = await _coord(plane).fanout("OP_ONE", {})
    assert result["status"] == "PARTIAL"
    assert result["ok"] == ["a"] and result["failed"] == ["b"]


async def test_fanout_reports_partial_when_one_member_raises():
    plane = FakePlane(["a", "b"], fail={"b"})
    result = await _coord(plane).fanout("OP_ONE", {})
    assert result["status"] == "PARTIAL"
    assert result["failed"] == ["b"]
    assert result["results"]["b"]["status"] == "ERROR"


async def test_fanout_all_failed_is_error():
    plane = FakePlane([])
    result = await _coord(plane).fanout("OP_ONE", {})
    assert result["status"] == "ERROR" and result["ok"] == []


async def test_fanout_with_no_members_is_an_error_not_a_vacuous_success():
    plane = FakePlane([])
    result = await _coord(plane, members=[]).fanout("OP_ONE", {})
    assert result["status"] == "ERROR"
    assert "no cluster members" in result["message"]


def test_member_links_carry_liveness():
    plane = FakePlane(["a"])
    links = _coord(plane).member_links()
    assert [l["id"] for l in links] == ["a", "b"]
    assert links[0]["connected"] is True and links[1]["connected"] is False
    assert links[0]["seconds_since_seen"] is not None


# ── ServiceWorkerClient dispatch ────────────────────────────────────────────

def _worker(ops=None):
    return ServiceWorkerClient(
        "node-a", "ws://127.0.0.1:1/ws/agent", "s3cret",
        ops if ops is not None else {"OP_ONE": lambda d: {"status": "SUCCESS", "echo": d}},
        default_port=8769)


def test_worker_requires_an_id_and_a_secret():
    with pytest.raises(ValueError):
        ServiceWorkerClient("", "ws://127.0.0.1/ws/agent", "s", {})
    with pytest.raises(ValueError):
        ServiceWorkerClient("a", "ws://127.0.0.1/ws/agent", "", {})


def test_worker_runs_only_ops_in_its_table():
    worker = _worker()
    assert worker.dispatch("OP_ONE", {"k": 1}) == {
        "member_id": "node-a", "status": "SUCCESS", "echo": {"k": 1}}
    for forbidden in ("RUN_COMMAND", "WRITE_FILE", "OP_TWO", None):
        out = worker.dispatch(forbidden, {})
        assert out["status"] == "ERROR"
        assert "unsupported worker operation" in out["message"]


def test_worker_op_exception_is_an_error_not_a_crash():
    def boom(_data):
        raise RuntimeError("disk on fire")
    out = _worker({"OP_ONE": boom}).dispatch("OP_ONE", {})
    assert out["status"] == "ERROR" and "disk on fire" in out["message"]


def test_worker_rejects_a_non_dict_op_result():
    out = _worker({"OP_ONE": lambda d: "ok"}).dispatch("OP_ONE", {})
    assert out["status"] == "ERROR" and "returned str" in out["message"]


def test_cluster_ports_are_distinct_from_each_other_and_the_known_listeners():
    taken = {8765, 8766, 8767, 8768}
    assert set(CLUSTER_PORTS.values()).isdisjoint(taken)
    assert len(set(CLUSTER_PORTS.values())) == len(CLUSTER_PORTS)


# ── End-to-end: one coordinator, two authenticated workers ──────────────────

class _Host(AgentHostingControlPlane):
    """Loopback-only agent host — no hub dial, no spoke registration."""

    MODULE_TYPE = "dns"
    AGENT_PORT_ENV = "LM_TEST_CLUSTER_PORT"
    AGENT_LOOPBACK_ENV = "LM_TEST_CLUSTER_LOOPBACK"
    AGENT_LISTENER_ENV = "LM_TEST_CLUSTER_LISTENER"
    AGENT_CONFIG_PATH = "/nonexistent/lm-test-cluster/config.json"
    AGENT_LISTENER_OPT_IN = False

    def _agent_listener_enabled(self):
        return True


async def test_two_authenticated_workers_are_driven_by_one_coordinator(tmp_path,
                                                                       monkeypatch):
    port = 18771
    monkeypatch.setenv("LM_TEST_CLUSTER_PORT", str(port))
    monkeypatch.setenv("LM_TEST_CLUSTER_LOOPBACK", "1")

    host = _Host("dns-coord")
    host.agent_secret = "shared-worker-psk"
    from security.signer import MessageSigner
    host.agent_signer = MessageSigner(host.agent_secret)

    server = asyncio.create_task(host.run_agent_server())
    await asyncio.sleep(0.6)

    applied = {"dns-a": [], "dns-b": []}

    def make_ops(member):
        return {"DNSW_APPLY": lambda d: (applied[member].append(d["version"])
                                         or {"status": "SUCCESS",
                                             "version": d["version"],
                                             "digest": d["digest"]}),
                "DNSW_STATE": lambda d: {"status": "SUCCESS",
                                         "version": (applied[member][-1]
                                                     if applied[member] else None)}}

    url = f"ws://127.0.0.1:{port}/ws/agent"
    workers = [ServiceWorkerClient(m, url, "shared-worker-psk", make_ops(m))
               for m in ("dns-a", "dns-b")]
    tasks = [asyncio.create_task(w.run()) for w in workers]
    try:
        for _ in range(60):
            if len(host.connected_agents) == 2:
                break
            await asyncio.sleep(0.1)
        assert sorted(host.connected_agents) == ["dns-a", "dns-b"], \
            "both workers must authenticate against the coordinator listener"

        coord = ClusterCoordinator("dns", ("DNSW_APPLY", "DNSW_STATE"),
                                   lambda: host, members=["dns-a", "dns-b"])
        assert coord.enabled is True
        result = await coord.fanout("DNSW_APPLY",
                                    {"version": 7, "digest": "abc", "records": []},
                                    timeout=10.0)
        assert result["status"] == "SUCCESS", result
        assert applied == {"dns-a": [7], "dns-b": [7]}

        state = await coord.fanout("DNSW_STATE", {}, timeout=10.0)
        assert {m: r["version"] for m, r in state["results"].items()} == {
            "dns-a": 7, "dns-b": 7}

        # One worker gone → the fan-out must degrade to PARTIAL, not SUCCESS.
        workers[1].stop()
        tasks[1].cancel()
        for _ in range(60):
            if len(host.connected_agents) == 1:
                break
            await asyncio.sleep(0.1)
        degraded = await coord.fanout(
            "DNSW_APPLY", {"version": 8, "digest": "def", "records": []},
            timeout=10.0)
        assert degraded["status"] == "PARTIAL"
        assert degraded["ok"] == ["dns-a"] and degraded["failed"] == ["dns-b"]
        assert applied["dns-b"] == [7]
    finally:
        for w in workers:
            w.stop()
        for t in tasks + [server]:
            t.cancel()
        for t in tasks + [server]:
            try:
                await t
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass


async def test_worker_refuses_a_wrong_secret(monkeypatch):
    """A worker that does not hold the PSK never reaches the op table."""
    port = 18772
    monkeypatch.setenv("LM_TEST_CLUSTER_PORT", str(port))
    monkeypatch.setenv("LM_TEST_CLUSTER_LOOPBACK", "1")
    host = _Host("dns-coord-2")
    host.agent_secret = "right-psk"
    from security.signer import MessageSigner
    host.agent_signer = MessageSigner(host.agent_secret)
    server = asyncio.create_task(host.run_agent_server())
    await asyncio.sleep(0.6)
    worker = ServiceWorkerClient("dns-x", f"ws://127.0.0.1:{port}/ws/agent",
                                 "wrong-psk", {"OP": lambda d: {"status": "SUCCESS"}})
    task = asyncio.create_task(worker.run())
    try:
        await asyncio.sleep(1.5)
        assert host.connected_agents == {}
    finally:
        worker.stop()
        for t in (task, server):
            t.cancel()
            try:
                await t
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass


# ── Worker PSK must never cross the network in plaintext (review #2) ────────

class TestCoordinatorURLNormalization:
    """``normalize_coordinator_url`` is the gate: the worker sends its shared
    PSK in the FIRST handshake frame, so a plaintext hop off-box publishes the
    cluster credential."""

    def test_bare_host_defaults_to_wss_on_the_module_port(self):
        assert normalize_coordinator_url("10.0.1.9", 8769) == \
            "wss://10.0.1.9:8769/ws/agent"

    def test_host_and_port_defaults_to_wss(self):
        assert normalize_coordinator_url("10.0.1.9:9999", 8769) == \
            "wss://10.0.1.9:9999/ws/agent"

    def test_explicit_wss_is_completed_not_replaced(self):
        assert normalize_coordinator_url("wss://dns.lab:8769", 8769) == \
            "wss://dns.lab:8769/ws/agent"
        assert normalize_coordinator_url("wss://dns.lab/ws/agent", 8769) == \
            "wss://dns.lab:8769/ws/agent"

    @pytest.mark.parametrize("url", [
        "ws://10.0.1.9:8769/ws/agent",
        "ws://dns.lab",
        "ws://192.168.5.5:8770",
    ])
    def test_remote_plaintext_is_rejected_not_upgraded(self, url):
        with pytest.raises(InsecureCoordinatorURL, match="refusing plaintext"):
            normalize_coordinator_url(url, 8769)

    @pytest.mark.parametrize("url", [
        "ws://127.0.0.1:8769/ws/agent",
        "ws://localhost:8769",
        "ws://[::1]:8769",
    ])
    def test_loopback_plaintext_is_allowed(self, url):
        """TLS terminates upstream on the co-located all-in-one path."""
        assert normalize_coordinator_url(url, 8769).startswith("ws://")

    def test_a_non_ws_scheme_is_rejected(self):
        with pytest.raises(ValueError, match="scheme must be ws/wss"):
            normalize_coordinator_url("https://dns.lab:8769", 8769)

    def test_empty_is_rejected(self):
        with pytest.raises(ValueError):
            normalize_coordinator_url("", 8769)


def test_worker_refuses_construction_against_a_remote_plaintext_coordinator():
    with pytest.raises(InsecureCoordinatorURL):
        ServiceWorkerClient("dns-a", "ws://10.0.1.9:8769/ws/agent", "psk",
                            {"OP": lambda d: {"status": "SUCCESS"}},
                            default_port=8769)


def test_worker_normalizes_a_bare_host_to_wss():
    worker = ServiceWorkerClient("dns-a", "10.0.1.9", "psk",
                                 {"OP": lambda d: {"status": "SUCCESS"}},
                                 default_port=8769)
    assert worker.url == "wss://10.0.1.9:8769/ws/agent"


def test_worker_builds_a_tls_context_for_wss():
    worker = ServiceWorkerClient("dns-a", "wss://10.0.1.9:8769/ws/agent", "psk",
                                 {"OP": lambda d: {"status": "SUCCESS"}},
                                 default_port=8769)
    ctx = worker._ssl_context()
    assert isinstance(ctx, ssl.SSLContext)


def test_worker_uses_no_tls_context_on_loopback():
    worker = ServiceWorkerClient("dns-a", "ws://127.0.0.1:8769/ws/agent", "psk",
                                 {"OP": lambda d: {"status": "SUCCESS"}},
                                 default_port=8769)
    assert worker._ssl_context() is None


def test_worker_refuses_to_connect_when_the_tls_context_cannot_be_built(monkeypatch):
    """Fail closed: a broken TLS config must not fall back to sending the PSK
    in the clear."""
    worker = ServiceWorkerClient("dns-a", "wss://10.0.1.9:8769/ws/agent", "psk",
                                 {"OP": lambda d: {"status": "SUCCESS"}},
                                 default_port=8769)
    monkeypatch.setattr("messaging.service_cluster.cluster_client_ssl_context",
                        lambda *a, **k: None)
    with pytest.raises(RuntimeError, match="refusing to send the worker secret"):
        worker._ssl_context()


class TestClusterClientSSLContext:
    """REGRESSION (review round 2, #1): verification is MANDATORY on this leg.
    There is no unverified mode — the worker hands over the shared PSK in its
    first frame."""

    def _ca(self, tmp_path):
        import subprocess
        ca = tmp_path / "ca.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(tmp_path / "k.pem"), "-out", str(ca),
             "-days", "1", "-subj", "/CN=lm-test-ca"],
            check=True, capture_output=True)
        return ca

    def test_default_verifies(self, monkeypatch):
        monkeypatch.delenv("LM_CLUSTER_CA_CERT", raising=False)
        monkeypatch.delenv("LM_HUB_CA_CERT", raising=False)
        monkeypatch.delenv("LM_CLUSTER_TLS_CHECK_HOSTNAME", raising=False)
        ctx = cluster_client_ssl_context()
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True

    def test_no_env_can_turn_verification_off(self, monkeypatch, tmp_path):
        """The old LM_CLUSTER_TLS_VERIFY=0 escape hatch must not exist."""
        monkeypatch.setenv("LM_CLUSTER_TLS_VERIFY", "0")
        monkeypatch.setenv("LM_CLUSTER_CA_CERT", str(self._ca(tmp_path)))
        ctx = cluster_client_ssl_context()
        assert ctx.verify_mode == ssl.CERT_REQUIRED

    def test_pinned_project_ca_is_loaded(self, monkeypatch, tmp_path):
        monkeypatch.setenv("LM_CLUSTER_CA_CERT", str(self._ca(tmp_path)))
        ctx = cluster_client_ssl_context()
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.get_ca_certs(), "the pinned CA must be loaded"

    def test_a_missing_ca_fails_closed(self, monkeypatch, tmp_path):
        monkeypatch.setenv("LM_CLUSTER_CA_CERT", str(tmp_path / "absent.pem"))
        assert cluster_client_ssl_context() is None, \
            "never fall back to an unverified context"

    def test_hostname_check_can_be_relaxed_but_the_cert_is_still_verified(
            self, monkeypatch, tmp_path):
        """Self-signed-by-IP coordinators: the SAN match is relaxed, the trust
        anchor is not."""
        monkeypatch.setenv("LM_CLUSTER_CA_CERT", str(self._ca(tmp_path)))
        monkeypatch.setenv("LM_CLUSTER_TLS_CHECK_HOSTNAME", "0")
        ctx = cluster_client_ssl_context()
        assert ctx.check_hostname is False
        assert ctx.verify_mode == ssl.CERT_REQUIRED

    def test_hub_ca_is_the_fallback_anchor(self, monkeypatch, tmp_path):
        monkeypatch.delenv("LM_CLUSTER_CA_CERT", raising=False)
        monkeypatch.setenv("LM_HUB_CA_CERT", str(self._ca(tmp_path)))
        ctx = cluster_client_ssl_context()
        assert ctx.get_ca_certs()


class _TLSRequiredHost(_Host):
    AGENT_LISTENER_REQUIRE_TLS = True
    AGENT_PORT_ENV = "LM_TEST_TLSREQ_PORT"
    AGENT_LOOPBACK_ENV = "LM_TEST_TLSREQ_LOOPBACK"


async def test_cluster_listener_refuses_to_bind_plaintext_on_all_interfaces(monkeypatch):
    """REGRESSION (review #2): a cert-less cluster listener used to fall back to
    the plaintext port on 0.0.0.0, publishing the worker PSK to the network."""
    monkeypatch.setenv("LM_TEST_TLSREQ_PORT", "18790")
    monkeypatch.delenv("LM_TEST_TLSREQ_LOOPBACK", raising=False)
    monkeypatch.delenv("LM_TLS_CERT", raising=False)
    monkeypatch.delenv("LM_TLS_KEY", raising=False)
    monkeypatch.setenv("LM_LE_LIVE_DIR", "/nonexistent-le-dir")
    host = _TLSRequiredHost("dns-coord-tls")
    with pytest.raises(ListenerRequiresTLS, match="plaintext"):
        await host.run_agent_server()


async def test_cluster_listener_still_binds_loopback_plaintext(monkeypatch):
    """TLS terminates upstream on the loopback path, so that stays allowed."""
    monkeypatch.setenv("LM_TEST_TLSREQ_PORT", "18791")
    monkeypatch.setenv("LM_TEST_TLSREQ_LOOPBACK", "1")
    monkeypatch.delenv("LM_TLS_CERT", raising=False)
    host = _TLSRequiredHost("dns-coord-lb")
    task = asyncio.create_task(host.run_agent_server())
    await asyncio.sleep(0.5)
    assert not task.done(), "the loopback bind must succeed"
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):  # noqa: BLE001
        pass


async def test_an_insecure_listener_is_not_retried(monkeypatch, caplog):
    """Retrying cannot produce a cert; the port must stay closed and say so."""
    monkeypatch.setenv("LM_TEST_TLSREQ_PORT", "18792")
    monkeypatch.delenv("LM_TEST_TLSREQ_LOOPBACK", raising=False)
    monkeypatch.delenv("LM_TLS_CERT", raising=False)
    monkeypatch.setenv("LM_LE_LIVE_DIR", "/nonexistent-le-dir")
    host = _TLSRequiredHost("dns-coord-noretry")
    host._start_agent_server_task()
    await asyncio.sleep(0.4)
    assert host._agent_server_task.done(), "the self-heal loop must NOT retry"


def test_pxmx_and_cs_listeners_keep_their_plaintext_fallback():
    """The require-TLS gate is opt-in: existing cert-less pxmx/cs deployments
    must be unaffected."""
    assert AgentHostingControlPlane.AGENT_LISTENER_REQUIRE_TLS is False



# ── Round 3, #2: ensure_cluster_listener reports REAL readiness ────────────

class _ReadyHost(_Host):
    """Cluster-shaped host: TLS required, own port env."""

    MODULE_TYPE = "dns"
    AGENT_PORT_ENV = "LM_TEST_READY_PORT"
    AGENT_LOOPBACK_ENV = "LM_TEST_READY_LOOPBACK"
    AGENT_LISTENER_ENV = "LM_TEST_READY_LISTENER"
    AGENT_LISTENER_REQUIRE_TLS = True

    def _agent_listener_enabled(self):
        return True


def _host(tmp_path, name="dns-coord"):
    host = _ReadyHost(name)
    host.AGENT_CONFIG_PATH = str(tmp_path / "lm-dns" / "config.json")
    return host


async def test_ensure_cluster_listener_waits_for_a_real_bind(tmp_path, monkeypatch):
    """REGRESSION: it used to return as soon as the task existed, so a bind or
    TLS failure surfaced asynchronously — after the API had already told the
    operator the cluster was configured."""
    monkeypatch.setenv("LM_TEST_READY_PORT", "18801")
    monkeypatch.setenv("LM_TEST_READY_LOOPBACK", "1")
    host = _host(tmp_path)
    try:
        result = await host.ensure_cluster_listener(timeout=10.0)
        assert result["ok"] is True and result["serving"] is True
        assert result["endpoint"].endswith(":18801")
        assert result["error"] == ""
        assert host.agent_secret, "the PSK is minted as part of readiness"
    finally:
        task = host._agent_server_task
        if task:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass


async def test_ensure_cluster_listener_reports_a_missing_certificate(tmp_path,
                                                                     monkeypatch):
    monkeypatch.setenv("LM_TEST_READY_PORT", "18802")
    monkeypatch.delenv("LM_TEST_READY_LOOPBACK", raising=False)
    monkeypatch.delenv("LM_TLS_CERT", raising=False)
    monkeypatch.delenv("LM_TLS_KEY", raising=False)
    monkeypatch.setenv("LM_LE_LIVE_DIR", "/nonexistent-le-dir")
    host = _host(tmp_path, "dns-coord-nocert")
    # Make the self-provisioning step fail so the TLS requirement bites.
    monkeypatch.setattr(host, "_provision_listener_cert", lambda: None)
    result = await host.ensure_cluster_listener(timeout=10.0)
    assert result["ok"] is False and result["serving"] is False
    assert "TLS certificate" in result["error"]


async def test_ensure_cluster_listener_reports_a_bind_collision(tmp_path,
                                                                monkeypatch):
    monkeypatch.setenv("LM_TEST_READY_PORT", "18803")
    monkeypatch.setenv("LM_TEST_READY_LOOPBACK", "1")
    holder = _host(tmp_path, "holder")
    await holder.ensure_cluster_listener(timeout=10.0)
    try:
        rival = _host(tmp_path, "rival")
        # 10 retries × 3s is longer than any sane API call; the readiness wait
        # must time out and SAY so rather than return success.
        result = await rival.ensure_cluster_listener(timeout=1.5)
        assert result["ok"] is False
        assert "did not start" in result["error"] or "in use" in result["error"]
        task = rival._agent_server_task
        if task:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
    finally:
        task = holder._agent_server_task
        if task:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass


async def test_a_disabled_listener_reports_ok_but_not_serving(tmp_path,
                                                              monkeypatch):
    monkeypatch.setenv("LM_TEST_READY_PORT", "18804")
    host = _host(tmp_path, "dns-single")
    host._agent_listener_enabled = lambda: False
    result = await host.ensure_cluster_listener(timeout=5.0)
    assert result == {"ok": True, "serving": False, "endpoint": "", "error": ""}
    assert host._agent_server_task is None


def test_a_hosted_role_self_provisions_a_listener_certificate(tmp_path,
                                                              monkeypatch):
    """REGRESSION (round 3, #2): an agent-HOSTED dns/dhcp role has no installer
    of its own, and the listener refuses plaintext — so without this a generic
    agent could never host a cluster."""
    monkeypatch.delenv("LM_TLS_CERT", raising=False)
    monkeypatch.delenv("LM_TLS_KEY", raising=False)
    monkeypatch.setenv("LM_LE_LIVE_DIR", "/nonexistent-le-dir")
    host = _host(tmp_path, "dns-hosted")
    host._provision_listener_cert()
    cert = tmp_path / "lm-dns" / "tls" / "coordinator.crt"
    key = tmp_path / "lm-dns" / "tls" / "coordinator.key"
    assert cert.is_file() and key.is_file()
    assert oct(os.stat(key).st_mode)[-3:] == "600"
    # Bound to THIS instance, never to the process environment: two co-loaded
    # cluster roles would otherwise serve each other's certificate.
    assert host._agent_listener_tls_paths() == (str(cert), str(key))
    assert "LM_TLS_CERT" not in os.environ


def test_cert_provisioning_is_skipped_when_tls_is_not_required(tmp_path,
                                                              monkeypatch):
    """pxmx/cs must be untouched."""
    monkeypatch.delenv("LM_TLS_CERT", raising=False)
    host = _host(tmp_path, "pxmx-like")
    host.AGENT_LISTENER_REQUIRE_TLS = False
    host._provision_listener_cert()
    assert not (tmp_path / "lm-dns" / "tls").exists()


# ── Round 4, #3: co-loaded dns + dhcp listeners are independent ────────────

class _DnsRoleHost(_ReadyHost):
    MODULE_TYPE = "dns"
    AGENT_PORT_ENV = "LM_TEST_DNSROLE_PORT"
    AGENT_LOOPBACK_ENV = "LM_TEST_DNSROLE_LOOPBACK"
    AGENT_TLS_CERT_ENV = "LM_DNS_TLS_CERT"
    AGENT_TLS_KEY_ENV = "LM_DNS_TLS_KEY"


class _DhcpRoleHost(_ReadyHost):
    MODULE_TYPE = "dhcp"
    AGENT_PORT_ENV = "LM_TEST_DHCPROLE_PORT"
    AGENT_LOOPBACK_ENV = "LM_TEST_DHCPROLE_LOOPBACK"
    AGENT_TLS_CERT_ENV = "LM_DHCP_TLS_CERT"
    AGENT_TLS_KEY_ENV = "LM_DHCP_TLS_KEY"


def _role_host(cls, tmp_path, module):
    host = cls(f"agent-1-{module}")
    host.AGENT_CONFIG_PATH = str(tmp_path / f"lm-{module}" / "config.json")
    return host


def test_co_loaded_roles_provision_distinct_listener_certificates(tmp_path,
                                                                  monkeypatch):
    """REGRESSION: os.environ.setdefault('LM_TLS_CERT', …) is process-global, so
    whichever cluster role started first supplied the certificate for BOTH — and
    a worker pinning its own role's cert then refused the other's listener."""
    for var in ("LM_TLS_CERT", "LM_TLS_KEY", "LM_DNS_TLS_CERT", "LM_DNS_TLS_KEY",
                "LM_DHCP_TLS_CERT", "LM_DHCP_TLS_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("LM_LE_LIVE_DIR", "/nonexistent-le-dir")

    dns = _role_host(_DnsRoleHost, tmp_path, "dns")
    dhcp = _role_host(_DhcpRoleHost, tmp_path, "dhcp")
    dns._provision_listener_cert()
    dhcp._provision_listener_cert()

    dns_cert, dns_key = dns._agent_listener_tls_paths()
    dhcp_cert, dhcp_key = dhcp._agent_listener_tls_paths()
    assert dns_cert != dhcp_cert and dns_key != dhcp_key
    assert dns_cert == str(tmp_path / "lm-dns" / "tls" / "coordinator.crt")
    assert dhcp_cert == str(tmp_path / "lm-dhcp" / "tls" / "coordinator.crt")
    assert os.path.isfile(dns_cert) and os.path.isfile(dhcp_cert)
    # And the process environment is NOT mutated by provisioning.
    assert "LM_TLS_CERT" not in os.environ


def test_provisioning_order_does_not_leak_between_roles(tmp_path, monkeypatch):
    for var in ("LM_TLS_CERT", "LM_TLS_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("LM_LE_LIVE_DIR", "/nonexistent-le-dir")
    dhcp = _role_host(_DhcpRoleHost, tmp_path, "dhcp")
    dhcp._provision_listener_cert()
    dns = _role_host(_DnsRoleHost, tmp_path, "dns")
    # The dns role has NOT provisioned yet and must not inherit dhcp's cert.
    assert dns._agent_listener_tls_paths() == ("", "")
    dns._provision_listener_cert()
    assert dns._agent_listener_tls_paths()[0] != dhcp._agent_listener_tls_paths()[0]


def test_role_specific_env_overrides_the_shared_one(tmp_path, monkeypatch):
    monkeypatch.setenv("LM_TLS_CERT", "/shared/any.crt")
    monkeypatch.setenv("LM_TLS_KEY", "/shared/any.key")
    monkeypatch.setenv("LM_DNS_TLS_CERT", "/role/dns.crt")
    monkeypatch.setenv("LM_DNS_TLS_KEY", "/role/dns.key")
    monkeypatch.delenv("LM_DHCP_TLS_CERT", raising=False)
    monkeypatch.delenv("LM_DHCP_TLS_KEY", raising=False)
    dns = _role_host(_DnsRoleHost, tmp_path, "dns")
    dhcp = _role_host(_DhcpRoleHost, tmp_path, "dhcp")
    assert dns._agent_listener_tls_paths() == ("/role/dns.crt", "/role/dns.key")
    # dhcp has no role-specific override → the shared one, as before.
    assert dhcp._agent_listener_tls_paths() == ("/shared/any.crt", "/shared/any.key")


async def test_dns_and_dhcp_listeners_serve_simultaneously(tmp_path, monkeypatch):
    """Both cluster roles must bind at the same time, each on its own port and
    with its own PSK, on one generic agent."""
    monkeypatch.setenv("LM_TEST_DNSROLE_PORT", "18811")
    monkeypatch.setenv("LM_TEST_DNSROLE_LOOPBACK", "1")
    monkeypatch.setenv("LM_TEST_DHCPROLE_PORT", "18812")
    monkeypatch.setenv("LM_TEST_DHCPROLE_LOOPBACK", "1")

    dns = _role_host(_DnsRoleHost, tmp_path, "dns")
    dhcp = _role_host(_DhcpRoleHost, tmp_path, "dhcp")
    tasks = []
    try:
        dns_ready = await dns.ensure_cluster_listener(timeout=10.0)
        dhcp_ready = await dhcp.ensure_cluster_listener(timeout=10.0)
        assert dns_ready["ok"] and dhcp_ready["ok"]
        assert dns_ready["endpoint"].endswith(":18811")
        assert dhcp_ready["endpoint"].endswith(":18812")
        # Independent PSKs: approving a dns worker must not authenticate a dhcp
        # one (their config paths, and therefore their secrets, are separate).
        assert dns.agent_secret and dhcp.agent_secret
        assert dns.agent_secret != dhcp.agent_secret
        assert dns.AGENT_CONFIG_PATH != dhcp.AGENT_CONFIG_PATH

        # Both sockets really are accepting.
        for port in (18811, 18812):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
        tasks = [dns._agent_server_task, dhcp._agent_server_task]
    finally:
        for task in tasks:
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass
