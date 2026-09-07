"""Role deploys must WAIT for the dpkg lock, not fail on it.

Observed failure: two role deploys on one node reported

    [GenericAgent] Deployment of 'dns-server' failed (rc=100)
    E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 24691 (apt-get)

Both roles named the SAME third-party pid, so the holder was neither deploy — it
was another apt user on the node (LM's own ``os_update`` dist-upgrade, or the
distro's unattended-upgrades timer). apt's default is to take the lock or die
instantly with rc=100, so a deploy that merely landed at a busy moment was
reported to the operator as a package failure.

The fix is ``DPkg::Lock::Timeout``, which makes apt queue for the lock instead.
It is applied two ways, and both matter:

* a node-wide ``/etc/apt/apt.conf.d`` drop-in, because the module install
  scripts shell out on their own and are not all reachable from the agent; and
* explicit ``-o`` flags on the installs the agent runs itself, so a node whose
  drop-in has not been written yet is still covered.
"""


import pytest

import agent_spoke


# ── the node-wide drop-in ─────────────────────────────────────────────────────

def test_the_dropin_tells_apt_to_wait(tmp_path):
    conf_dir = tmp_path / "apt.conf.d"
    conf_dir.mkdir()
    target = conf_dir / "99lm-lock-timeout"

    assert agent_spoke.ensure_apt_lock_timeout(str(target)) is True
    assert 'DPkg::Lock::Timeout "600";' in target.read_text()


def test_the_dropin_is_idempotent_and_does_not_rewrite(tmp_path):
    """Written on every agent start, so a no-op re-run must not churn the file."""
    conf_dir = tmp_path / "apt.conf.d"
    conf_dir.mkdir()
    target = conf_dir / "99lm-lock-timeout"

    agent_spoke.ensure_apt_lock_timeout(str(target))
    first = target.stat().st_mtime_ns
    assert agent_spoke.ensure_apt_lock_timeout(str(target)) is True
    assert target.stat().st_mtime_ns == first


def test_a_stale_dropin_is_corrected(tmp_path):
    """A node carrying an older/hand-edited value must be brought back in line."""
    conf_dir = tmp_path / "apt.conf.d"
    conf_dir.mkdir()
    target = conf_dir / "99lm-lock-timeout"
    target.write_text('DPkg::Lock::Timeout "5";\n')

    assert agent_spoke.ensure_apt_lock_timeout(str(target)) is True
    assert 'DPkg::Lock::Timeout "600";' in target.read_text()
    assert '"5"' not in target.read_text()


def test_a_non_debian_host_is_left_alone(tmp_path):
    """No /etc/apt/apt.conf.d means no apt. Must not create the tree or raise."""
    target = tmp_path / "nope" / "apt.conf.d" / "99lm-lock-timeout"
    assert agent_spoke.ensure_apt_lock_timeout(str(target)) is False
    assert not target.exists()


def test_startup_never_raises_when_not_root(tmp_path, monkeypatch):
    """The agent must still start on a node where it cannot write apt config."""
    conf_dir = tmp_path / "apt.conf.d"
    conf_dir.mkdir()
    target = conf_dir / "99lm-lock-timeout"

    def _denied(*a, **k):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(agent_spoke.Path, "write_text", _denied)
    assert agent_spoke.ensure_apt_lock_timeout(str(target)) is False


# ── the installs the agent runs itself ────────────────────────────────────────

@pytest.mark.parametrize("role", ["dns", "dhcp", "le", "ldap"])
def test_every_role_install_waits_for_the_lock(role):
    """Each apt argv must carry the wait, and carry it as an apt-get OPTION.

    Ordering matters: options have to precede the ``install`` sub-command,
    otherwise apt reads them as package names.
    """
    argv = _install_argv_for(role)

    assert "-o" in argv
    assert f"DPkg::Lock::Timeout={agent_spoke._APT_LOCK_TIMEOUT_S}" in argv
    assert argv.index("-o") < argv.index("install"), \
        "apt options must come before the install sub-command"


def test_the_subprocess_timeout_outlasts_the_lock_wait():
    """Otherwise we kill apt for doing exactly what we asked: waiting.

    The old value was 180s. A 600s lock wait under a 180s kill would have turned
    a successful queue into a TimeoutExpired — the same failure with a new name.
    """
    assert agent_spoke._APT_INSTALL_TIMEOUT_S > agent_spoke._APT_LOCK_TIMEOUT_S


def _install_argv_for(role):
    """Pull the apt argv the agent would run for ``role`` out of _install_role_inner.

    Reads the literal dict rather than driving the whole coroutine: the dict is
    the thing under test and the surrounding method does git clones and pip.
    """
    import inspect
    src = inspect.getsource(agent_spoke.GenericAgent._install_role_inner)
    assert "install_cmds" in src
    ns = {"_APT_LOCK_FLAGS": agent_spoke._APT_LOCK_FLAGS}
    body = src[src.index("install_cmds = {"):]
    body = body[:body.index("\n        }") + len("\n        }")]
    exec(body.strip().replace("\n        ", "\n"), ns)
    return ns["install_cmds"][role]
