"""Build a network topology graph from what the fleet can actually tell us.

Four sources, in descending order of trust:

1. **Operator-declared links** — what a human asserted directly in the nw
   topology UI. The most explicit statement available, and the escape hatch
   for anything the other three sources get wrong.
2. **LLDP** (``NW_GET_LLDP_NEIGHBORS``) — a device naming its neighbour and the
   port it is on. Authoritative and LIVE: both ends agreed to advertise right
   now.
3. **NetBox cables** — an operator's cable inventory (``NETBOX_GET_CABLES``),
   authoritative for gear the nw fleet never logs into at all (unmanaged
   switches, media converters, PDUs, older APs) and would otherwise be
   invisible on the map. Ranked below LLDP only because a cable record can go
   stale (gear re-patched without updating NetBox) in a way a live LLDP
   adjacency cannot.
4. **MAC-table inference** — a switch port that has learned exactly ONE MAC is
   almost certainly a direct link to whatever owns that MAC. A port that has
   learned many is an uplink or a trunk carrying a whole downstream segment,
   which says nothing about what is *directly* attached, so it is recorded as a
   trunk and NOT drawn as a link.

Every edge carries its ``source`` and the graph never silently mixes them, so
the UI can show an inferred link as provisional and an operator can promote it
to a declared one.

Pure functions over plain dicts: no hub, no I/O, no spoke calls. The route
gathers the inputs; everything here is deterministic and unit-testable, which
matters because the interesting failures are all about *identity* — the same
switch arriving as a chassis MAC from LLDP, an IP from NetBox and a UUID from
the nw fleet must collapse to ONE node or the map grows phantom devices.
"""
# re matches IP/MAC/hostname shapes; typing hints document the dict shapes.
import re
from typing import Any, Dict, List, Optional

# MAC helpers: port classification, the station-MAC filter, and MAC normalization.
from nw_topology_macs import classify_ports, is_topology_mac, norm_mac


#: Edge provenance, most trusted first. Used to decide which edge wins when two
#: sources describe the same link.
SOURCE_RANK = {"manual": 0, "lldp": 1, "netbox": 2, "mac": 3}


def _s(value: Any) -> str:
    """Return value as a stripped string, with None becoming ""."""
    return "" if value is None else str(value).strip()


def _short_hostname(name: str) -> str:
    """``host.example.com`` -> ``host`` (casefolded), so an LLDP FQDN and a
    NetBox short name are one device. "" when there is no domain to strip or
    the name is an IP / MAC literal or free text."""
    # Only a dotted, real hostname (not an IP, MAC, or free text) has a short form.
    name = _s(name)
    if ("." not in name or _IP_NAME_RE.match(name) or _MAC_NAME_RE.match(name)
            or not _HOSTNAME_RE.match(name)):
        return ""
    # Keep the first label, case-folded.
    return name.split(".", 1)[0].casefold()


def _key_candidates(rec: Dict[str, Any]) -> List[str]:
    """Identity keys for one record, strongest first.

    A device shows up under different names depending on who is describing it,
    so each record contributes every identifier it knows and the alias table
    below unions them. Order matters: the first candidate becomes the node's
    canonical id, so a real fleet id always beats a MAC, which beats an IP,
    which beats a name.
    """
    # Collect keys in strength order: fleet id, MACs, IPs, then names.
    out = []
    # Fleet device id is the strongest identity.
    did = _s(rec.get("id"))
    if did:
        out.append("dev:" + did)
    # Every valid station MAC the record carries.
    for field in ("chassis", "mac", "base_mac", "remote_chassis"):
        mac = norm_mac(_s(rec.get(field)))
        if mac and is_topology_mac(mac):
            out.append("mac:" + mac)
    # Every IP field, with any /prefix removed.
    for field in ("address", "ip", "primary_ip", "remote_mgmt_ip", "mgmt_ip"):
        ip = _s(rec.get(field)).split("/")[0]
        if ip:
            out.append("ip:" + ip)
    # Names, case-folded, plus the short form of an FQDN so "sw1" and "sw1.lab" match.
    for field in ("name", "remote_name", "hostname"):
        name = _s(rec.get(field))
        if name:
            out.append("name:" + name.casefold())
            short = _short_hostname(name)
            if short:
                out.append("name:" + short)
    # De-dupe, preserving order.
    seen = set()
    return [k for k in out if not (k in seen or seen.add(k))]


class _Aliases:
    """Union-find over identity keys.

    Needed because identity arrives incrementally and transitively: LLDP gives
    us ``mac:00:0b:...`` + ``name:olks-edge-1``, NetBox later gives us
    ``name:olks-edge-1`` + ``ip:172.16.1.91``, and only together do we learn the
    MAC and the IP are the same box. Merging pairwise as records arrive, rather
    than resolving at the end, keeps that from depending on input order.
    """

    def __init__(self):
        """Start with an empty parent map; each key is added lazily as its own root."""
        # key -> parent key; a key whose parent is itself is a set root.
        self._parent: Dict[str, str] = {}

    def find(self, key: str) -> str:
        """Return the root of key's set, adding key as a new singleton if unseen."""
        # Register unseen keys as their own root.
        self._parent.setdefault(key, key)
        # Walk parent links up to the root.
        root = key
        while self._parent[root] != root:
            root = self._parent[root]
        # Point every key on the walked path straight at the root for faster future lookups.
        while self._parent[key] != root:  # path compression
            self._parent[key], key = root, self._parent[key]
        return root

    def union(self, keys: List[str]) -> str:
        """Merge every key into one set and return its root. The FIRST key wins
        as the root so a strong identifier (a fleet id) stays canonical rather
        than being replaced by whichever alias happened to be seen first."""
        # Ignore empty keys; nothing left means nothing to merge.
        keys = [k for k in keys if k]
        if not keys:
            return ""
        # The first key's root becomes the root of the merged set.
        root = self.find(keys[0])
        # Attach every other key's root under it.
        for other in keys[1:]:
            other_root = self.find(other)
            if other_root != root:
                self._parent[other_root] = root
        return root


class TopologyBuilder:
    """Accumulates nodes and edges, then renders a graph."""

    def __init__(self, trunk_threshold: int = 4):
        """Set up empty node/edge/trunk stores and the identity alias table.

        Args:
            trunk_threshold: MAC count at which a switch port is treated as a trunk.
        """
        # Ports learning at least this many MACs are trunks, not direct links.
        self.trunk_threshold = trunk_threshold
        # Union-find that merges the different identifiers of one device.
        self.aliases = _Aliases()
        # Nodes by canonical id, edges by (a, a_port, b, b_port), and trunk records.
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._edges: Dict[tuple, Dict[str, Any]] = {}
        self._trunks: List[Dict[str, Any]] = []

    # ── nodes ────────────────────────────────────────────────────────────────
    def add_node(self, rec: Dict[str, Any], kind: str, source: str) -> str:
        """Register (or enrich) a node and return its canonical id.

        Returns "" for a record carrying no usable identifier at all, which the
        callers treat as "nothing to draw" rather than inventing a node.
        """
        # Every identity key this record offers; with none there is nothing to add.
        keys = _key_candidates(rec)
        if not keys:
            return ""
        # Any node already filed under one of these keys BEFORE the union. The
        # union can re-root the set (a stronger identifier arriving later wins),
        # which would otherwise orphan the node stored under the old root and
        # silently split one device into two -- exactly the phantom-device
        # failure this class exists to prevent.
        # Remove nodes stored under any of these keys' current roots so they can be merged.
        prior = []
        for key in keys:
            old_root = self.aliases.find(key)
            if old_root in self._nodes and self._nodes[old_root] not in prior:
                prior.append(self._nodes[old_root])
            self._nodes.pop(old_root, None)
        # Merge all keys into one set; collect ids of prior nodes that will disappear.
        root = self.aliases.union(keys)
        old_ids = {n["id"] for n in prior if n["id"] != root}

        # Build the merged node from the prior nodes, or create a fresh one.
        node = None
        # The most specific node (a fleet switch over a bare LLDP neighbour)
        # is the merge base, so its identity is what survives.
        prior.sort(key=lambda n: _KIND_RANK.get(n["kind"], 99))
        # First prior node becomes the base under the new root; others merge into it.
        for existing in prior:
            if node is None:
                node = existing
                node["id"] = root
            else:
                _merge_node(node, existing)
        # No prior node: create an empty node of this kind.
        if node is None:
            node = {"id": root, "name": "", "kind": kind, "sources": [],
                    "addresses": [], "macs": [], "device_id": "", "tenant_id": "",
                    "object_type": "", "model": "", "site": "", "role": "",
                    "lldp_capable": False, "manual": False}
        # Store the node under its canonical id.
        self._nodes[root] = node
        # Edges already drawn against a merged-away id must follow the node.
        self._repoint_edges(old_ids, root)
        # Record which source mentioned this node.
        if source not in node["sources"]:
            node["sources"].append(source)
        # A more specific kind wins: "switch" learned from the fleet should not
        # be flattened back to "endpoint" by a later MAC-table sighting.
        if _KIND_RANK.get(kind, 99) < _KIND_RANK.get(node["kind"], 99):
            node["kind"] = kind
        # Take the record's name if it is a better name than the current one.
        rec_name = (_s(rec.get("name")) or _s(rec.get("remote_name"))
                    or _s(rec.get("hostname")))
        if _better_name(node["name"], rec_name):
            node["name"] = rec_name
        # Fill the fleet device id and other descriptive fields only when still empty.
        if not node["device_id"] and _s(rec.get("id")):
            node["device_id"] = _s(rec.get("id"))
        for field in ("tenant_id", "object_type", "model", "site", "role"):
            if not node[field] and _s(rec.get(field)):
                node[field] = _s(rec.get(field))
        # Add any new IP addresses the record carries.
        for field in ("address", "ip", "primary_ip", "remote_mgmt_ip", "mgmt_ip"):
            ip = _s(rec.get(field)).split("/")[0]
            if ip and ip not in node["addresses"]:
                node["addresses"].append(ip)
        # Add any new valid station MACs the record carries.
        for field in ("chassis", "mac", "base_mac", "remote_chassis"):
            mac = norm_mac(_s(rec.get(field)))
            if mac and is_topology_mac(mac) and mac not in node["macs"]:
                node["macs"].append(mac)
        # Mark nodes the operator declared by hand.
        if rec.get("manual"):
            node["manual"] = True
        return root

    def resolve(self, rec: Dict[str, Any]) -> str:
        """Canonical id for a record WITHOUT creating a node.

        Used by MAC inference: a MAC we have never otherwise heard of should
        not by itself conjure a device onto the map — it becomes an endpoint
        only if the caller decides to add one.
        """
        # Return the first key whose set already has a node.
        for key in _key_candidates(rec):
            root = self.aliases.find(key)
            if root in self._nodes:
                return root
        return ""

    def current(self, node_id: str) -> str:
        """Live canonical id for an id returned earlier by ``add_node``.

        A later ``add_node`` can merge that node into a set rooted elsewhere
        (a NetBox record sharing the fleet device's IP, an LLDP neighbour that
        is the same box), so a cached id must be re-resolved before use.
        """
        # Empty ids resolve to nothing.
        if not node_id:
            return ""
        # Follow the alias table; only return it if a node exists there.
        root = self.aliases.find(node_id)
        return root if root in self._nodes else ""

    def _repoint_edges(self, old_ids: set, new_root: str) -> None:
        """Move edges off ids that were just merged away.

        A link can be drawn before the node it lands on gains a stronger
        identifier, so rewriting the node alone would leave the edge pointing at
        an id no longer present in ``nodes`` — an invisible link in the UI.
        """
        # Nothing merged away means nothing to move.
        if not old_ids:
            return
        # Edges touching any merged-away id.
        stale = [e for e in self._edges.values()
                 if e["a"] in old_ids or e["b"] in old_ids]
        if not stale:
            return
        # Remove them, then re-add each with the merged-away end replaced by the new root.
        for edge in stale:
            key = (edge["a"], edge["a_port"], edge["b"], edge["b_port"])
            self._edges.pop(key, None)
        for edge in stale:
            a = new_root if edge["a"] in old_ids else edge["a"]
            b = new_root if edge["b"] in old_ids else edge["b"]
            self.add_edge(a, edge["a_port"], b, edge["b_port"],
                          edge["source"], edge["detail"])

    # ── edges ────────────────────────────────────────────────────────────────
    def add_edge(self, a_id: str, a_port: str, b_id: str, b_port: str,
                 source: str, detail: str = "") -> None:
        """Add one link. Undirected: the pair is sorted so A→B and B→A collapse.

        Both ends of an LLDP adjacency normally report it, and without this the
        map would draw every switch-to-switch link twice.
        """
        # Ignore edges with a missing end or a self-loop.
        if not a_id or not b_id or a_id == b_id:
            return
        # Sort the two ends so the same link has one key regardless of direction.
        ends = sorted([(a_id, _s(a_port)), (b_id, _s(b_port))])
        key = (ends[0][0], ends[0][1], ends[1][0], ends[1][1])
        # Edge record to store or merge.
        edge = {
            "source": source, "detail": detail,
            "a": ends[0][0], "a_port": ends[0][1],
            "b": ends[1][0], "b_port": ends[1][1],
        }
        # New link: store it as-is.
        existing = self._edges.get(key)
        if existing is None:
            self._edges[key] = edge
            return
        # Keep the most trusted description of the same link.
        if SOURCE_RANK.get(source, 99) < SOURCE_RANK.get(existing["source"], 99):
            self._edges[key] = edge

    def add_trunk(self, node_id: str, port: str, count: int) -> None:
        """Record a port that learned too many MACs to be a direct link (a trunk/uplink)."""
        # Kept for the UI's "declare this link yourself" hints.
        self._trunks.append({"node": node_id, "port": _s(port), "mac_count": count})

    # ── output ───────────────────────────────────────────────────────────────
    def render(self) -> Dict[str, Any]:
        """Return the finished graph: sorted nodes, edges, trunk hints, and summary stats."""
        # Sort nodes for a stable output and flag which ones count as infrastructure.
        nodes = sorted(self._nodes.values(), key=lambda n: (n["kind"], n["name"], n["id"]))
        for node in nodes:
            node["infra"] = _is_infra(node)
        # Sort edges for a stable output and count them per source.
        edges = sorted(self._edges.values(),
                       key=lambda e: (e["a"], e["a_port"], e["b"], e["b_port"]))
        by_source: Dict[str, int] = {}
        for edge in edges:
            by_source[edge["source"]] = by_source.get(edge["source"], 0) + 1
        # Resolve trunk ports to the owning node's display name. The UI lists
        # these as "declare this link yourself" hints, and a raw internal node
        # id is useless in that table. Sorted so the list is stable across loads.
        names = {n["id"]: n["name"] for n in nodes}
        trunks = sorted(
            ({**t, "node_name": names.get(t["node"], "")} for t in self._trunks),
            key=lambda t: (t["node_name"], t["port"]))
        # Graph plus stats the UI shows in its summary bar.
        return {
            "nodes": nodes,
            "edges": edges,
            "trunks": trunks,
            "stats": {
                "nodes": len(nodes),
                "edges": len(edges),
                "edges_by_source": by_source,
                "trunk_ports": len(trunks),
                "nodes_without_lldp": sum(1 for n in nodes if not n["lldp_capable"]),
                "infra_nodes": sum(1 for n in nodes if n["infra"]),
            },
        }


#: Lower is more specific. Governs which label survives when a device is seen
#: as several things (fleet switch AND a MAC on someone else's port).
_KIND_RANK = {"switch": 0, "gateway": 0, "device": 1, "manual": 1,
              "neighbor": 2, "endpoint": 3}


def _merge_node(dst: Dict[str, Any], src: Dict[str, Any]) -> None:
    """Fold one node's knowledge into another when they turn out to be the
    same device. Never discards a fact: the whole purpose of the merge is that
    each view held something the other lacked."""
    # Keep the more specific kind and the better name.
    if _KIND_RANK.get(src["kind"], 99) < _KIND_RANK.get(dst["kind"], 99):
        dst["kind"] = src["kind"]
    if _better_name(dst["name"], src["name"]):
        dst["name"] = src["name"]
    # Fill descriptive fields the destination lacks.
    for field in ("device_id", "tenant_id", "object_type", "model",
                  "site", "role"):
        if not dst[field] and src[field]:
            dst[field] = src[field]
    # Union the list fields without duplicates.
    for field in ("sources", "addresses", "macs"):
        for value in src[field]:
            if value not in dst[field]:
                dst[field].append(value)
    # Boolean flags are sticky: true on either side stays true.
    dst["lldp_capable"] = dst["lldp_capable"] or src["lldp_capable"]
    dst["manual"] = dst["manual"] or src["manual"]

#: nw ``object_type`` → topology node kind.
_OBJECT_KIND = {"aos_switch": "switch", "cx_switch": "switch",
                "ex_switch": "switch", "gateway": "gateway"}

# Plain hostname characters.
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
# MAC literals in colon/dash, dotted-triplet, or bare 12-hex form.
_MAC_NAME_RE = re.compile(r"^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$|^(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}$"
                          r"|^[0-9a-f]{12}$", re.IGNORECASE)
#: NetBox auto-discovery names unknown hosts ``device-<mac>``.
_NETBOX_PLACEHOLDER_RE = re.compile(r"^device-[0-9a-f]{12}$", re.IGNORECASE)
# Dotted IPv4 literal used as a name.
_IP_NAME_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
#: Tokens that older nw parsers lifted out of LLDP system descriptions.
_JUNK_NAMES = frozenset({"x86_64", "aarch64", "amd64", "localhost", "none", "(none)"})


def _is_real_hostname(name: str) -> bool:
    """A name an operator would recognise: not a MAC, not NetBox's
    ``device-<mac>`` placeholder, not free-text LLDP junk."""
    # A real hostname has valid characters, at least one letter, and is none of the junk,
    # MAC, or NetBox-placeholder forms.
    name = _s(name)
    return bool(name and _HOSTNAME_RE.match(name)
                and re.search(r"[A-Za-z]", name)
                and name.casefold() not in _JUNK_NAMES
                and not _MAC_NAME_RE.match(name)
                and not _NETBOX_PLACEHOLDER_RE.match(name))


def _better_name(current: str, candidate: str) -> bool:
    """Whether ``candidate`` should replace a node's ``current`` name: fill an
    empty one, or upgrade a bare MAC / IP / NetBox placeholder to a real
    hostname. A real hostname is kept -- LLDP junk must not rename it.

    Fleet switches added by address are named after their IP; the hostname
    only arrives via a neighbour's LLDP or NetBox, and keeping the IP left
    the map full of ``172.21.x.y`` labels next to unlinked NetBox rows."""
    # An empty candidate never replaces anything.
    if not _s(candidate):
        return False
    # Any non-empty candidate fills an empty name.
    current = _s(current)
    if not current:
        return True
    # Only replace a placeholder name (MAC, IP, device-<mac>) and only with a real hostname.
    is_placeholder = bool(_MAC_NAME_RE.match(current)
                          or _IP_NAME_RE.match(current)
                          or _NETBOX_PLACEHOLDER_RE.match(current))
    return is_placeholder and _is_real_hostname(candidate)


def _is_infra(node: Dict[str, Any]) -> bool:
    """Whether a node is infrastructure (switch, firewall, hypervisor, ...)
    rather than an endpoint known only by a MAC.

    The map's default view shows infrastructure only. Fleet devices and
    operator declarations always count; anything else must carry a real
    hostname (not a MAC, not NetBox's ``device-<mac>`` placeholder, not the
    free-text junk some LLDP agents advertise) AND corroboration -- a NetBox
    record, an LLDP advertisement, or a management address.
    """
    # Read the node's kind and the sources that mentioned it.
    kind = _s(node.get("kind"))
    sources = node.get("sources") or []
    # Switches, gateways, and operator-declared nodes are always infrastructure.
    if kind in ("switch", "gateway") or kind == "manual" or node.get("manual"):
        return True
    # Anything from the managed fleet is infrastructure.
    if "fleet" in sources:
        return True
    # Otherwise a real hostname is required.
    if not _is_real_hostname(node.get("name")):
        return False
    # A device advertising its own hostname over LLDP (switches, hypervisors
    # running lldpd) is infrastructure even with NetBox unavailable and no
    # management address in the advertisement.
    return ("netbox" in sources or "lldp" in sources
            or bool(node.get("addresses")))


#: LLDP capability codes ("B:R") that older nw parsers stored as the remote port.
_LLDP_CAPS_RE = re.compile(r"^[BRWPCSTOAHDr](?:[:,][BRWPCSTOAHDr])*$")


def _lldp_port(value: Any) -> str:
    """Return the LLDP remote port, or "" when the value is really a capability code."""
    port = _s(value)
    return "" if _LLDP_CAPS_RE.match(port) else port


def _same_switch_groups(fleet, lldp_by_device) -> Dict[str, str]:
    """Map each duplicate fleet device id to the canonical id it duplicates.

    The scanner adds a switch once per address it answers on (every SVI, the
    VSX virtual IP), so one CX pair showed up as fifteen fleet devices named
    ``172.21.x.y``. Each copy returns the same LLDP table, and a neighbour
    port ``(chassis, port)`` faces exactly one device, so an identical set of
    real neighbour ports (at least two) means the same box. Rows without a
    real chassis MAC, remote port and local port are ignored, which keeps
    junk LLDP from merging unrelated devices.
    """
    # Index fleet devices by id.
    id_to_dev = {_s(dev.get("id")): dev for dev in (fleet or [])
                 if isinstance(dev, dict) and _s(dev.get("id"))}
    # fingerprint (set of neighbour ports) -> fleet ids sharing it.
    fingerprints = {}
    # Build an LLDP fingerprint for each fleet device.
    for dev_id, dev in id_to_dev.items():
        rows = (lldp_by_device or {}).get(dev_id) or []
        fingerprint_rows = []
        # Keep only rows with a valid chassis MAC, remote port, and meaningful local port.
        for row in rows:
            if not isinstance(row, dict):
                continue
            mac = norm_mac(_s(row.get("remote_chassis")))
            if not mac or not is_topology_mac(mac):
                continue
            remote_port = _lldp_port(row.get("remote_port"))
            local_port = _s(row.get("local_port"))
            if not remote_port or not local_port:
                continue
            if not re.search(r"[A-Za-z0-9]", local_port):
                continue
            fingerprint_rows.append((mac, remote_port, local_port))
        # Need at least two neighbour ports for a trustworthy fingerprint.
        fingerprint = frozenset(fingerprint_rows)
        if len(fingerprint) < 2:
            continue
        # Group device ids by identical fingerprint.
        if fingerprint not in fingerprints:
            fingerprints[fingerprint] = []
        fingerprints[fingerprint].append(dev_id)

    # duplicate id -> canonical id.
    result = {}
    # Each group of two or more ids is one physical switch.
    for group in fingerprints.values():
        if len(group) < 2:
            continue
        # Prefer the copy that has a real hostname as canonical, else the first one.
        canonical = None
        for dev_id in group:
            dev = id_to_dev[dev_id]
            if _is_real_hostname(_s(dev.get("name"))):
                canonical = dev_id
                break
        if canonical is None:
            canonical = group[0]
        # Map every other copy to the canonical id.
        for dev_id in group:
            if dev_id != canonical:
                result[dev_id] = canonical
    return result


def _drop_nic_agents(rows):
    """Drop a NIC firmware's own LLDP agent (e.g. "Broadcom P225p NetXtreme-E
    ...") when the host behind that NIC also advertises on the same port: its
    chassis is a sibling MAC of the host's (same first 5 octets) and its name
    is free text, so keeping it puts a phantom device on the map."""
    # Only dict rows are considered.
    good = [r for r in rows if isinstance(r, dict)]
    # local port -> set of MAC prefixes (first 5 octets) of hosts with a real name there.
    hosts = {}
    for r in good:
        name = _s(r.get("remote_name"))
        mac = norm_mac(_s(r.get("remote_chassis")))
        if name and " " not in name and is_topology_mac(mac):
            hosts.setdefault(_s(r.get("local_port")), set()).add(mac[:14])
    # Keep every row except free-text-named agents whose MAC is a sibling of a host on
    # the same port.
    out = []
    for r in good:
        name = _s(r.get("remote_name"))
        mac = norm_mac(_s(r.get("remote_chassis")))
        if " " in name and is_topology_mac(mac) and mac[:14] in hosts.get(_s(r.get("local_port")), ()):
            continue
        out.append(r)
    return out


def _pairwise_identities(builder, lldp_seen) -> None:
    """Match two fleet devices that see each other on the same port pair.

    X says "lp -> rp" and exactly one other fleet device W says "rp -> lp":
    W's row describes X (and X's row describes W), even when both are
    fleet entries named only by IP address.
    """
    # Index every LLDP row by its (local port, remote port) pair.
    index = {}
    for entry_idx, (dev, nid, rows) in enumerate(lldp_seen):
        for lp, _, rp, raw in rows:
            if lp and rp:
                index.setdefault((lp, rp), []).append((entry_idx, raw))

    # Collect identity merges implied by matching port pairs.
    merges = []
    for entry_idx, (dev_x, nid_x, rows) in enumerate(lldp_seen):
        for lp, _, rp, raw_x in rows:
            # Need both ports to match anything.
            if not lp or not rp:
                continue
            # Find exactly one other device reporting the reverse pair (rp -> lp).
            back = [(j, raw_w) for (j, raw_w) in index.get((rp, lp), []) if j != entry_idx]
            if len(back) != 1:
                continue
            # And this pair itself must be unique, or the match is ambiguous.
            if len(index.get((lp, rp), [])) != 1:
                continue
            # Each side's row describes the other device, so queue both merges.
            j, raw_w = back[0]
            dev_w, nid_w, _ = lldp_seen[j]
            merges.append((dev_x, nid_x, raw_w))
            merges.append((dev_w, nid_w, raw_x))

    # Apply each merge to the node's current canonical id.
    for dev, nid, raw in merges:
        x = builder.current(nid)
        if not x:
            continue
        # Identity fields from the neighbour's row; skip rows with nothing useful.
        rec = {"id": dev, "remote_chassis": _s(raw.get("remote_chassis")), "remote_name": _s(raw.get("remote_name")), "remote_mgmt_ip": _s(raw.get("remote_mgmt_ip"))}
        if not any(rec[k] for k in ("remote_chassis", "remote_name", "remote_mgmt_ip")):
            continue
        # Merge that identity into the node, keeping its kind.
        builder.add_node(rec, builder._nodes[x]["kind"], "lldp")


def _reciprocal_identities(builder, lldp_seen) -> None:
    """Name fleet devices from what their LLDP neighbours say about them.

    A gateway added by address is "172.21.2.3" in the fleet, while CRSW1
    advertises it as "MIPBE-SSPLM-N31-VPNC1" (chassis 00:1a:...) on 1/1/43.
    The gateway's own table says GE0/0/2 -> CRSW1 port 1/1/43, so CRSW1's
    row whose remote port is GE0/0/2 (and local port 1/1/43) describes the
    gateway itself. Only a candidate that every such neighbour agrees on is
    merged; two VPNCs both on GE0/0/2 with unknown far ports stay apart.
    ``lldp_seen``: (fleet_dev_id, local_node_id, [(local_port,
    remote_node_id, remote_port, raw_row), ...]).
    """
    # Gather every LLDP row reported by each (current) node, resolving neighbour ids.
    by_node = {}
    for fleet_dev_id, local_node_id, rows in lldp_seen:
        x = builder.current(local_node_id)
        if not x:
            continue
        if x not in by_node:
            by_node[x] = []
        by_node[x].extend([(lp, builder.current(y_raw), rp, raw_row) for lp, y_raw, rp, raw_row in rows if builder.current(y_raw)])

    # For each fleet device, find what its neighbours say about it.
    for fleet_dev_id, local_node_id, rows in lldp_seen:
        x = builder.current(local_node_id)
        if not x:
            continue
        # Intersection of identities every neighbour agrees on (None = not yet constrained).
        candidates = None
        # Check each of this device's LLDP rows.
        for lp, y_raw, rp, _ in rows:
            # Skip rows with no resolved neighbour, self-references, or no local port.
            y = builder.current(y_raw)
            if not y or y == x or y not in by_node or not lp:
                continue
            # The neighbour's rows pointing back on our local port (and our remote port if known).
            matches = set()
            for lp2, z, rp2, raw2 in by_node[y]:
                if rp2 == lp and (not rp or lp2 == rp) and z != y:
                    matches.add((_s(raw2.get("remote_chassis")), _s(raw2.get("remote_name")), _s(raw2.get("remote_mgmt_ip"))))
            # This neighbour has no matching row; it adds no constraint.
            if not matches:
                continue
            # Narrow the candidate set to what this neighbour also agrees on.
            candidates = matches if candidates is None else candidates & matches
        # Exactly one agreed identity: merge it into the fleet device's node.
        if candidates and len(candidates) == 1:
            c, n, ip = next(iter(candidates))
            if any([c, n, ip]):
                kind = builder._nodes[x]["kind"]
                builder.add_node({"id": fleet_dev_id, "remote_chassis": c, "remote_name": n, "remote_mgmt_ip": ip}, kind, "lldp")

def _collapse_half_edges(builder) -> None:
    """Drop an LLDP edge whose far port is unknown when the other end
    reported the same link with both ports (otherwise drawn twice)."""
    # Snapshot edges so removals do not disturb the iteration.
    edges = list(builder._edges.items())
    # Only LLDP edges with exactly one port known are candidates for removal.
    for key, e in edges:
        if e["source"] != "lldp" or (e["a_port"] and e["b_port"]):
            continue
        if not e["a_port"] and not e["b_port"]:
            continue
        # The two nodes and the one port that is known.
        target_node_a = e["a"]
        target_node_b = e["b"]
        target_port = e["a_port"] if e["a_port"] else e["b_port"]
        # Look for a complete LLDP edge between the same nodes using that same port.
        other_edge = None
        for key2, f in edges:
            # Skip itself, non-LLDP edges, edges between other nodes, and incomplete edges.
            if key2 == key or f["source"] != "lldp":
                continue
            if {f["a"], f["b"]} != {target_node_a, target_node_b}:
                continue
            if not f["a_port"] or not f["b_port"]:
                continue
            # Match on whichever end carries the known port.
            if e["a_port"]:
                if f["a_port"] == target_port and f["a"] == target_node_a:
                    other_edge = f
                    break
            else:
                if f["b_port"] == target_port and f["b"] == target_node_b:
                    other_edge = f
                    break
        # A complete duplicate exists, so drop the half edge.
        if other_edge:
            builder._edges.pop(key, None)


def _lag_aliases(builder, macs_by_device, fleet_ids, duplicate_of, trusted):
    """Map logical ports (LAGs) that LLDP never names to their neighbour.

    LLDP reports the physical member (1/1/51) but AOS-CX learns MACs on the
    LAG (lag251). The neighbour's own chassis MAC shows up in the MAC table on
    that LAG, so a LAG whose chassis-MAC hits all point to one LLDP neighbour
    faces that neighbour.
    """
    # (local node, port) -> neighbour node.
    result = {}
    # Analyse each polled switch's MAC table.
    for d, rows in macs_by_device.items():
        # Skip duplicate fleet rows and devices without a node.
        if d in duplicate_of:
            continue
        local = builder.current(fleet_ids.get(d, ""))
        if not local:
            continue
        # From the edges, not ``trusted``: a port can carry two LLDP
        # neighbours (a host plus its NIC's firmware agent) and ``trusted``
        # keeps only one of them per port.
        # A host may advertise its NIC MAC as the LLDP port id; that MAC is
        # what the switch learns, so it identifies the neighbour too.
        # Non-MAC neighbours of this switch, and MACs their LLDP port ids reveal.
        neighbours = set()
        port_macs = {}
        for e in builder._edges.values():
            if e["source"] != "mac" and local in (e["a"], e["b"]):
                nb, nb_port = (e["b"], e["b_port"]) if e["a"] == local else (e["a"], e["a_port"])
                neighbours.add(nb)
                pm = norm_mac(_s(nb_port))
                if pm and is_topology_mac(pm):
                    port_macs.setdefault(nb, set()).add(pm)
        # mac -> owning neighbour (None when more than one neighbour claims it).
        neighbours.discard(local)
        mac_owner = {}
        for nb in neighbours:
            for mac in list(builder._nodes.get(nb, {}).get("macs", [])) + sorted(port_macs.get(nb, ())):
                if mac in mac_owner:
                    if mac_owner[mac] != nb:
                        mac_owner[mac] = None
                else:
                    mac_owner[mac] = nb
        # port -> set of neighbours whose MACs were learned on that port.
        hits = {}
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            # Read the port and MAC; count only MACs that belong to a known neighbour.
            port = str(row.get("interface") or "").strip()
            mac = norm_mac(str(row.get("mac") or ""))
            if port and mac and mac in mac_owner:
                nb = mac_owner[mac]
                if nb is not None:
                    if port not in hits:
                        hits[port] = set()
                    hits[port].add(nb)
        # A port all of whose neighbour hits point at one neighbour faces that neighbour,
        # unless LLDP already names it.
        for port, nb_set in hits.items():
            if len(nb_set) == 1 and (local, port) not in trusted:
                result[(local, port)] = next(iter(nb_set))
    return result


def _attach_endpoints(builder, macs_by_device, fleet_ids, duplicate_of, trunk_threshold):
    """Place every endpoint MAC from the polled switches' MAC tables on the
    port (or non-polled downstream device) where it is physically attached.

    A MAC is learned on every switch between it and the poller, so sightings
    on an uplink toward another POLLED switch are ignored (that switch reports
    the true location). Of the rest, the port with the fewest MACs is the most
    specific. A port facing a non-polled LLDP/NetBox neighbour (a TOR, a
    hypervisor) means the MAC lives behind that neighbour, so it hangs off it.
    Nodes that already have a trusted link are left alone.
    """
    # Canonical nodes of the switches whose MAC tables were polled.
    polled = set()
    for d, rows in macs_by_device.items():
        if d in duplicate_of:
            continue
        current = builder.current(fleet_ids.get(d, ""))
        if current:
            polled.add(current)
    
    # (node, port) -> neighbour from trusted (non-MAC) links, and the nodes they touch.
    trusted = {}
    linked = set()
    for e in builder._edges.values():
        if e["source"] == "mac":
            continue
        a, b = e["a"], e["b"]
        trusted[(a, e["a_port"])] = b
        trusted[(b, e["b_port"])] = a
        linked.add(a)
        linked.add(b)
    # Add LAG ports whose neighbour was inferred from MAC hits.
    trusted.update(_lag_aliases(builder, macs_by_device, fleet_ids, duplicate_of, trusted))
    
    # mac -> list of (port MAC count, switch, port, neighbour) sightings, and mac -> IP.
    cands = {}
    ip_of = {}
    # Remember the IP of any MAC-table row that carries one.
    for rows in macs_by_device.values():
        for r in rows or []:
            if isinstance(r, dict) and _s(r.get("ip")):
                ip_of.setdefault(norm_mac(_s(r.get("mac"))), _s(r.get("ip")))
    # Collect candidate locations for each MAC from every polled switch.
    for d, rows in macs_by_device.items():
        if d in duplicate_of:
            continue
        local = builder.current(fleet_ids.get(d, ""))
        if not local:
            continue
        # Classify the switch's ports by MAC count.
        ports = classify_ports(rows or [], trunk_threshold=trunk_threshold)
        for port, info in ports.items():
            # Skip ports facing another polled switch; that switch reports the real location.
            nb = trusted.get((local, port))
            if nb in polled:
                continue
            # Unknown multi-MAC port: record it as a trunk hint.
            if nb is None and info["count"] >= trunk_threshold:
                builder.add_trunk(local, port, info["count"])
            # Each MAC on the port is a candidate location.
            for mac in info["macs"]:
                cands.setdefault(mac, []).append((info["count"], local, port, nb or ""))
    
    # MACs that belong to the polled switches themselves.
    own = set()
    for n in polled:
        if n in builder._nodes:
            own.update(builder._nodes[n].get("macs", []))
    
    # Place each MAC once, in a stable order.
    for mac in sorted(cands):
        # A switch's own MAC is not an endpoint.
        if mac in own:
            continue
        # Choose the sighting on the port with the fewest MACs (most specific).
        best = min(cands[mac])
        count, sw, port, nb = best
        # Reuse an existing node for the MAC, else create an endpoint node.
        node = builder.resolve({"mac": mac}) or builder.add_node(
            {"mac": mac, "name": mac, "ip": ip_of.get(mac, "")}, "endpoint", "mac")
        # Do not link to the switch itself, its neighbour, or another polled switch.
        if not node or node in (sw, nb) or node in polled:
            continue
        # Nodes with a trusted link keep it instead of an inferred one.
        if node in linked:
            continue
        # Inherit the switch's tenant when the endpoint has none.
        ep = builder._nodes.get(node) or {}
        if not ep.get("tenant_id"):
            ep["tenant_id"] = (builder._nodes.get(sw) or {}).get("tenant_id", "")
        # Behind a non-polled neighbour: hang the endpoint off it; else link to the switch port.
        if nb:
            builder.add_edge(nb, "", node, "", "mac", f"behind {port} ({count} MACs)")
        else:
            builder.add_edge(sw, port, node, "", "mac", "single MAC learned on port" if count == 1 else f"{count} MACs learned on port")


def build_topology(fleet: Optional[List[dict]] = None,
                   lldp_by_device: Optional[Dict[str, list]] = None,
                   macs_by_device: Optional[Dict[str, list]] = None,
                   netbox_devices: Optional[List[dict]] = None,
                   netbox_cables: Optional[List[dict]] = None,
                   manual_devices: Optional[List[dict]] = None,
                   manual_links: Optional[List[dict]] = None,
                   trunk_threshold: int = 4,
                   infer_from_macs: bool = True) -> Dict[str, Any]:
    """Assemble the graph.

    ``fleet``           nw device records (id/name/object_type/address/tenant_id)
    ``lldp_by_device``  device id → NW_GET_LLDP_NEIGHBORS rows
    ``macs_by_device``  device id → NW_GET_MAC_TABLE rows
    ``netbox_devices``  NetBox inventory rows (name/primary_ip/role/site/model)
    ``netbox_cables``   NetBox cable rows (NETBOX_GET_CABLES:
                        a_device/a_port/b_device/b_port/status/label)
    ``manual_devices``  operator-declared devices that speak no LLDP
    ``manual_links``    operator-declared links

    Ordering is deliberate. Inventory first so that by the time MAC inference
    runs, as many MACs as possible already resolve to a NAMED device; then LLDP
    and NetBox cables, so declared and inferred links can both see which ports
    are already spoken for; then inference last, filling only the gaps.
    """
    # One builder accumulates everything.
    builder = TopologyBuilder(trunk_threshold=trunk_threshold)

    # ── 1. Inventory: the nw fleet ──────────────────────────────────────────
    # fleet id -> node id, and duplicate fleet copies -> canonical id.
    fleet_ids: Dict[str, str] = {}
    duplicate_of = _same_switch_groups(fleet, lldp_by_device)
    # Add every fleet device as a node.
    for dev in (fleet or []):
        if not isinstance(dev, dict):
            continue
        # Kind from the nw object type (default "device").
        kind = _OBJECT_KIND.get(_s(dev.get("object_type")), "device")
        rec = dev
        # A duplicate copy is added under its canonical id.
        if _s(dev.get("id")) in duplicate_of:
            # Fold the copy's address/name into the canonical device. A VRRP /
            # active-gateway VIP is scanned under one peer's name but answered
            # by the other (its LLDP table proves which), so a conflicting
            # hostname is dropped — keeping it would alias, and merge, both
            # members of a VSX pair into one node.
            canon_id = duplicate_of[_s(dev.get("id"))]
            canon = next((c for c in fleet if isinstance(c, dict)
                          and _s(c.get("id")) == canon_id), {})
            rec = dict(dev, id=canon_id)
            if _s(dev.get("name")).casefold() != _s(canon.get("name")).casefold():
                rec.pop("name", None)
                rec.pop("hostname", None)
        # Remember the node id for this fleet device.
        node_id = builder.add_node(rec, kind, "fleet")
        if node_id:
            fleet_ids[_s(dev.get("id"))] = node_id

    # ── 2. Inventory: NetBox ────────────────────────────────────────────────
    # NetBox knows about hardware the nw fleet has never logged into, which is
    # most of what an operator wants on a topology map. It contributes nodes
    # and identity (name ⇄ IP) here; its cables are folded in as links below.
    # Add NetBox inventory devices as nodes.
    for dev in (netbox_devices or []):
        if not isinstance(dev, dict):
            continue
        builder.add_node(dev, "device", "netbox")

    # ── 3. Operator-declared devices (the no-LLDP case) ─────────────────────
    # Add operator-declared devices, flagged manual.
    for dev in (manual_devices or []):
        if not isinstance(dev, dict):
            continue
        rec = dict(dev)
        rec["manual"] = True
        builder.add_node(rec, _s(dev.get("kind")) or "manual", "manual")

    # ── 4. LLDP adjacencies ─────────────────────────────────────────────────
    # Per fleet device: (fleet id, node id, [(local port, neighbour node, remote port, row)]).
    lldp_seen: List[tuple] = []
    for device_id, rows in (lldp_by_device or {}).items():
        if _s(device_id) in duplicate_of:
            continue  # same table as its canonical device
        # The node this LLDP table belongs to; tables for unknown devices are skipped.
        local_id = (builder.current(fleet_ids.get(_s(device_id), ""))
                    or builder.resolve({"id": device_id}))
        if not local_id:
            continue
        # A device that returned LLDP rows speaks LLDP.
        if rows:
            builder._nodes[local_id]["lldp_capable"] = True
        # Rows recorded for the identity passes that follow.
        seen_rows: List[tuple] = []
        lldp_seen.append((_s(device_id), local_id, seen_rows))
        # Add each advertised neighbour (minus NIC firmware agents) as a node plus an edge.
        for row in _drop_nic_agents(rows or []):
            neighbour = {
                "remote_chassis": row.get("remote_chassis"),
                "remote_name": row.get("remote_name"),
                "remote_mgmt_ip": row.get("remote_mgmt_ip"),
            }
            # Create or enrich the neighbour node; skip rows with no usable identity.
            remote_id = builder.add_node(neighbour, "neighbor", "lldp")
            if not remote_id:
                continue
            builder._nodes[remote_id]["lldp_capable"] = True
            # The local node may have been re-rooted by the add above; use its current id.
            local_id = builder.current(local_id)
            builder.add_edge(local_id, row.get("local_port"),
                             remote_id, _lldp_port(row.get("remote_port")),
                             "lldp", _s(row.get("remote_descr")))
            # Remember the row for the reciprocal identity passes.
            seen_rows.append((_s(row.get("local_port")), remote_id,
                              _lldp_port(row.get("remote_port")), row))
    # Merge identities that LLDP implies, then remove half-known duplicate edges.
    _pairwise_identities(builder, lldp_seen)
    _reciprocal_identities(builder, lldp_seen)
    _collapse_half_edges(builder)

    # ── 5. Operator-declared links ──────────────────────────────────────────
    # Declared BEFORE inference so a human assertion always occupies the port
    # and inference cannot contradict it.
    # Add each operator-declared link between two resolvable nodes.
    for link in (manual_links or []):
        if not isinstance(link, dict):
            continue
        # The link ends may be given as id, name, MAC, or IP; try all of them.
        a_id = builder.resolve({"id": link.get("a"), "name": link.get("a"),
                                "mac": link.get("a"), "ip": link.get("a")})
        b_id = builder.resolve({"id": link.get("b"), "name": link.get("b"),
                                "mac": link.get("b"), "ip": link.get("b")})
        if not a_id or not b_id:
            continue
        builder.add_edge(a_id, link.get("a_port"), b_id, link.get("b_port"),
                         "manual", _s(link.get("note")))

    # ── 6. NetBox cables ─────────────────────────────────────────────────────
    # An operator's cable inventory — the one link source that can place gear
    # the nw fleet never logs into (unmanaged switches, PDUs, patch panels)
    # onto the map. Declared AFTER manual links (a human override in the nw UI
    # always wins) but BEFORE inference (a real cable record beats a guess).
    # Add each NetBox cable whose two device ends are already on the map.
    for cable in (netbox_cables or []):
        if not isinstance(cable, dict):
            continue
        a_id = builder.resolve({"name": cable.get("a_device")})
        b_id = builder.resolve({"name": cable.get("b_device")})
        if not a_id or not b_id:
            continue  # the device end isn't on the map (filtered out upstream)
        builder.add_edge(a_id, cable.get("a_port"), b_id, cable.get("b_port"),
                         "netbox", _s(cable.get("label")))

    # ── 7. MAC-table endpoint placement ─────────────────────────────────────
    # Place endpoint MACs from switch MAC tables, unless inference is turned off.
    if infer_from_macs:
        _attach_endpoints(builder, macs_by_device or {}, fleet_ids,
                          duplicate_of, trunk_threshold)

    # ── 8. Logical units: VSX pairs fold into one switch, stacks are tagged ──
    # Detect VSX pairs, render the graph, then fold pairs and tag stacks.
    pairs = _vsx_pairs(builder, lldp_seen)
    return _logical_units(builder.render(), pairs)


def _vsx_pairs(builder, lldp_seen) -> List[tuple]:
    """Polled switch pairs that behave as one VSX switch.

    nw collects no VSX state, so the pair is read from LLDP: the two switches
    are cabled to each other (the ISL / keepalive) AND at least two other
    devices are dual-homed to both on the SAME local port number (MCLAG
    members are wired symmetrically). Two independent switches that merely
    uplink to each other share no such ports, so they stay separate.
    """
    # switch node -> set of (local port, neighbour node) it sees over LLDP.
    seen: Dict[str, set] = {}
    # Only polled switches are candidates.
    for _dev, nid, rows in lldp_seen:
        me = builder.current(nid)
        if not me or builder._nodes[me]["kind"] != "switch":
            continue
        ports = seen.setdefault(me, set())
        # Record each LLDP neighbour on a named local port.
        for local_port, remote_id, _rp, _raw in rows:
            remote = builder.current(remote_id)
            if remote and remote != me and local_port:
                ports.add((local_port, remote))
    # Compare every pair of switches once; a switch joins at most one pair.
    ids = sorted(seen)
    pairs, used = [], set()
    for i, x in enumerate(ids):
        for y in ids[i + 1:]:
            if x in used or y in used:
                continue
            # They must be cabled to each other ...
            linked = any(r == y for _, r in seen[x]) or any(r == x for _, r in seen[y])
            # ... and share at least two other neighbours on the same local port numbers.
            shared = ({p for p in seen[x] if p[1] not in (x, y)}
                      & {p for p in seen[y] if p[1] not in (x, y)})
            if linked and len({r for _, r in shared}) >= 2:
                pairs.append((x, y))
                used.update((x, y))
    return pairs


def _unit_name(n1: str, n2: str) -> str:
    """Generate unit name by removing common prefix up to last '-' or '.'."""
    # Length of the common leading characters of the two names.
    i = 0
    while i < len(n1) and i < len(n2) and n1[i] == n2[i]:
        i += 1
    # No common prefix: show both full names.
    if i == 0:
        return n1 + " / " + n2
    # Back up to just after the last '-' or '.' inside the common prefix.
    prefix_end = 0
    for j in range(i - 1, -1, -1):
        if n1[j] in "-.":
            prefix_end = j + 1
            break
    # Show the first name in full and only the differing tail of the second.
    suffix = n2[prefix_end:]
    return n1 + " / " + suffix

def _logical_units(graph: dict, vsx_pairs: list) -> dict:
    """Fold each VSX pair into one logical switch node and tag stacks.

    Edges keep the member's real port and gain ``a_member``/``b_member`` (the
    member's name) so the UI can label them and the NetBox cable sync still
    lands on the physical member. The ISL between the members is internal to
    the unit and is listed on it as ``isl`` instead of drawn. A VSF/backplane
    stack already answers as one device; its member numbers are read from its
    ports (``1/1/x``, ``2/1/x``) into ``stack_members``.
    """
    # Unpack the rendered graph.
    nodes = graph["nodes"]
    edges = graph["edges"]
    trunks = graph["trunks"]
    stats = graph["stats"]

    # Members already folded, the new unit nodes, and member id -> (unit id, member name).
    used = set()
    units = []
    node_map = {node["id"]: node for node in nodes}
    new_nodes = []
    member_of = {}

    # Turn each VSX pair into one unit node.
    for x, y in vsx_pairs:
        # Skip pairs with unknown or already-used members.
        if x not in node_map or y not in node_map or x in used or y in used:
            continue
        # Order members by name; the unit id joins both member ids.
        members = sorted([node_map[x], node_map[y]], key=lambda n: n["name"])
        unit_id = "unit:" + members[0]["id"] + "+" + members[1]["id"]
        # Start from the first member's data and overwrite the unit-level fields.
        unit_node = members[0].copy()
        unit_node.update({
            "id": unit_id,
            "name": _unit_name(members[0]["name"], members[1]["name"]),
            "kind": "switch",
            "infra": True,
            "unit": "vsx",
            "members": [
                {
                    "id": m["id"],
                    "name": m["name"],
                    "device_id": m["device_id"],
                    "macs": m["macs"][:],
                    "addresses": m["addresses"][:],
                    "sources": m["sources"][:],
                    "tenant_id": m["tenant_id"]
                } for m in members
            ],
            "sources": list(dict.fromkeys(members[0]["sources"] + members[1]["sources"])),
            "addresses": list(dict.fromkeys(members[0]["addresses"] + members[1]["addresses"])),
            "macs": list(dict.fromkeys(members[0]["macs"] + members[1]["macs"])),
            "lldp_capable": members[0]["lldp_capable"] or members[1]["lldp_capable"],
            "manual": members[0]["manual"] or members[1]["manual"],
            "tenant_id": next((m["tenant_id"] for m in members if m["tenant_id"]), "")
        })
        # Record the unit and map both members to it.
        units.append(unit_node)
        used.add(x)
        used.add(y)
        member_of[x] = (unit_id, members[0]["name"])
        member_of[y] = (unit_id, members[1]["name"])

    # Rewrite edges onto units, dropping duplicates.
    new_edges = []
    edge_set = set()
    for edge in edges:
        a = edge["a"]
        b = edge["b"]
        a_member = ""
        b_member = ""
        # Edge between the two members of one unit: record it as the unit's ISL, not an edge.
        if a in member_of and b in member_of and member_of[a][0] == member_of[b][0]:
            # Same unit, drop edge but record isl
            unit_id = member_of[a][0]
            for u in units:
                if u["id"] == unit_id:
                    if "isl" not in u:
                        u["isl"] = []
                    u["isl"].append({
                        "a_member": member_of[a][1],
                        "a_port": edge["a_port"],
                        "b_member": member_of[b][1],
                        "b_port": edge["b_port"]
                    })
            continue
        # Repoint member ends onto their unit, keeping the member name for labels.
        new_edge = edge.copy()
        if a in member_of:
            new_edge["a"] = member_of[a][0]
            new_edge["a_member"] = member_of[a][1]
        if b in member_of:
            new_edge["b"] = member_of[b][0]
            new_edge["b_member"] = member_of[b][1]
        # Keep only one copy of identical rewritten edges.
        key = (new_edge.get("a", ""), new_edge.get("a_port", ""), new_edge.get("a_member", ""),
               new_edge.get("b", ""), new_edge.get("b_port", ""), new_edge.get("b_member", ""))
        if key not in edge_set:
            edge_set.add(key)
            new_edges.append(new_edge)

    # Repoint trunk hints onto units as well, keeping the member name.
    new_trunks = []
    for trunk in trunks:
        node = trunk["node"]
        if node in member_of:
            new_trunk = trunk.copy()
            new_trunk["node"] = member_of[node][0]
            new_trunk["member"] = member_of[node][1]
            new_trunk["node_name"] = trunk.get("node_name", "")
            new_trunks.append(new_trunk)
        else:
            new_trunks.append(trunk)

    # Replace member nodes with their unit nodes.
    nodes = [n for n in nodes if n["id"] not in used] + units
    # Matches stacked port names like "1/1/5" or "2/A3"; group 1 is the stack member number.
    port_re = re.compile(r"^(\d+)/(\d+/)?[A-Za-z]?\d+$")
    # node -> set of stack member numbers seen in its edge ports.
    node_ports = {}
    for edge in new_edges:
        a = edge["a"]
        b = edge["b"]
        a_port = edge.get("a_port", "")
        b_port = edge.get("b_port", "")
        if a not in node_ports:
            node_ports[a] = set()
        if b not in node_ports:
            node_ports[b] = set()
        if port_re.match(a_port):
            node_ports[a].add(int(port_re.match(a_port).group(1)))
        if port_re.match(b_port):
            node_ports[b].add(int(port_re.match(b_port).group(1)))

    # A node with ports on two or more members (none 0) is a stack.
    for node in nodes:
        node_id = node["id"]
        if node_id in node_ports:
            ports = list(node_ports[node_id])
            if len(ports) >= 2 and all(p != 0 for p in ports):
                node["stack_members"] = sorted(ports)
                if "unit" not in node:
                    node["unit"] = "stack"

    # Recompute stats for the folded graph.
    stats["logical_units"] = len(units)
    stats["nodes"] = len(nodes)
    by_source = {}
    for edge in new_edges:
        by_source[edge["source"]] = by_source.get(edge["source"], 0) + 1
    stats["edges_by_source"] = by_source
    stats["edges"] = len(new_edges)
    stats["trunk_ports"] = len(new_trunks)
    stats["nodes_without_lldp"] = sum(1 for n in nodes if not n.get("lldp_capable", False))
    stats["infra_nodes"] = sum(1 for n in nodes if n.get("infra", False))

    # Store the rewritten lists back into the graph.
    graph["nodes"] = nodes
    graph["edges"] = new_edges
    graph["trunks"] = new_trunks

    # Sort for a stable output.
    graph["nodes"].sort(key=lambda n: (n["kind"], n["name"], n["id"]))
    graph["edges"].sort(key=lambda e: (e.get("a", ""), e.get("a_port", ""), e.get("b", ""), e.get("b_port", "")))

    return graph


def netbox_lldp_links(graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The graph's LLDP-confirmed links as ``NETBOX_SYNC_LLDP`` payload rows.

    Each end carries every identity the merge learned (name, MACs, IPs, the nw
    fleet id) so the NetBox spoke can match it SERIAL/MAC-first and only fall
    back to the name. A server NIC usually advertises its MAC as the LLDP port
    id; when its port description is a short single token (``nic1``, not NIC
    firmware text) that is the readable interface name instead.
    Only edges with both ports known are emitted, de-duplicated by
    (name, port) pairs.
    """
    # Index nodes by id.
    nodes = {n.get("id"): n for n in (graph or {}).get("nodes") or []
             if isinstance(n, dict)}

    def end(node):
        """Return the identity block (name, MACs, IPs, fleet id) sent for one cable end."""
        # Only fleet nodes carry an nw device id.
        return {"name": _s(node.get("name")),
                "macs": list(node.get("macs") or []),
                "addresses": list(node.get("addresses") or []),
                "nw_device_id": (_s(node.get("device_id"))
                                 if "fleet" in (node.get("sources") or []) else "")}

    def port(p, detail):
        """Return a readable port name: a short port description replaces a MAC-style port id."""
        # If the port is a MAC and the detail is a single short token, use the detail.
        p = _s(p)
        if re.fullmatch(r"[0-9a-f]{12}", re.sub(r"[:.\-]", "", p.lower())) \
                and re.fullmatch(r"[A-Za-z0-9][\w./-]{0,31}", detail or ""):
            return detail
        return p

    def member(node, name):
        # A VSX unit is not a NetBox device; its cable lands on the member.
        """Return the VSX member named name, or the node itself when it is not a unit member."""
        for m in (node or {}).get("members") or []:
            if name and m.get("name") == name:
                return m
        return node

    # Output rows and keys already emitted.
    out, seen = [], set()
    # Turn each LLDP edge into a NetBox cable row.
    for edge in (graph or {}).get("edges") or []:
        # Only LLDP-sourced edges are sent.
        if not isinstance(edge, dict) or edge.get("source") != "lldp":
            continue
        # Resolve VSX units back to their physical members.
        a = member(nodes.get(edge.get("a")), _s(edge.get("a_member")))
        b = member(nodes.get(edge.get("b")), _s(edge.get("b_member")))
        # Both ends and both ports must be known.
        if not a or not b or not _s(edge.get("a_port")) or not _s(edge.get("b_port")):
            continue
        # Build the row with readable port names.
        detail = _s(edge.get("detail"))
        link = {"a": end(a), "a_port": port(edge.get("a_port"), detail),
                "b": end(b), "b_port": port(edge.get("b_port"), detail)}
        # De-duplicate by lower-cased names and ports.
        key = (link["a"]["name"].lower(), link["a_port"],
               link["b"]["name"].lower(), link["b_port"])
        if key in seen:
            continue
        seen.add(key)
        out.append(link)
    return out
