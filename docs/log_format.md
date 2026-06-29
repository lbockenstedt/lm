# Log Format Specification

All Lab Manager modules use a single structured log format so BugFixer can identify the failing module and route fixes automatically.

## Format

```
%(asctime)s - %(name)s - %(levelname)s - %(message)s
```

### Fields

| Field | Content | Example |
|-------|---------|---------|
| `%(asctime)s` | ISO-like timestamp | `2026-06-19 14:23:01,456` |
| `%(name)s` | Logger name — always the class name | `ProxmoxSpoke`, `LDAPManager`, `Hub` |
| `%(levelname)s` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` | `ERROR` |
| `%(message)s` | Human-readable message | `Agent 'pve-01' disconnected` |

## Configuration

Every module sets this format at startup:

```python
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("ClassName")
```

Use the class name as the logger name so BugFixer can map a log line back to the source file:

```python
# proxmox_spoke.py
logger = logging.getLogger("ProxmoxSpoke")

# ldap_manager.py
logger = logging.getLogger("LDAPManager")

# hub main.py
logger = logging.getLogger("Hub")
```

## BugFixer Integration

BugFixer parses `%(name)s` to identify which class/file emitted the error, then looks up the corresponding repo and creates a fix PR.

Expected log location per service (all file-backed logs live under `/var/log/lm/`, provisioned by `install_all.sh`):

| Service | Log file |
|---------|----------|
| Hub | `/var/log/lm/hub.log` |
| pxmx spoke | `/var/log/lm/lm-pxmx.log` |
| dns spoke | `/var/log/lm/lm-dns.log` |
| dhcp spoke | `/var/log/lm/lm-dhcp.log` |
| netbox spoke | depends on sibling-repo installer — `install_all.sh` clones `github.com/lbockenstedt/netbox.git` and runs its `install.sh`; check the cloned unit's `StandardOutput` for the file path. |
| ldap spoke | depends on sibling-repo installer — `install_all.sh` clones `github.com/lbockenstedt/ldap.git` and runs `install_ldap.sh`; check the cloned unit's `StandardOutput` for the file path. |
| cppm spoke | depends on sibling-repo installer — `install_all.sh` clones `github.com/lbockenstedt/cppm.git` and runs its `install.sh`; check the cloned unit's `StandardOutput` for the file path. |
| opnsense spoke | **journald only** — `journalctl -u lm-opnsense` (no file redirect; `install_opnsense.sh` ships no `StandardOutput`/`StandardError` redirect). |
| cs spoke | **journald only** — `journalctl -u lm-cs` (no file redirect) |

> The cs (Client Sim) and opnsense spoke systemd units do **not** redirect
> `StandardOutput`/`StandardError` to a file; their logs go to journald
> exclusively. Read them with `journalctl -u lm-cs -f` / `journalctl -u
> lm-opnsense -f`. The file-logged spokes (pxmx, dns, dhcp, …) append to the
> file listed above. The netbox/ldap/cppm spokes are installed from sibling
> repos by `install_all.sh`; their log paths are whatever their own installer
> provisions — confirm by inspecting the deployed unit rather than assuming a
> fixed `/var/log/lm/lm-<module>.log` path.

> No `kvm/` module ships in this repository, so there is no `lm-kvm` log path.
> See [operations.md](operations.md) for the runbook, and
> [installation.md](installation.md) §Co-Existence for the KVM status.

Agent logs (AGENT_LOG messages from agents to spokes) are relayed to the hub and forwarded to BugFixer via the hub's log relay endpoint.

## Rules

- Do not change the format — BugFixer's regex is pinned to this pattern.
- Never log secrets, passwords, or tokens in full. Redact with `secret[:4]…secret[-4:]` if partial context is needed.
- `%(name)s` must be the class name, not `__name__` (which would be the module/file name and changes on refactors).
