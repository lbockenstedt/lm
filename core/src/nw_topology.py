"""Build a network topology graph from what the fleet can actually tell us.

Three sources, in descending order of trust:

1. **LLDP** (``NW_GET_LLDP_NEIGHBORS``) — a device naming its neighbour and the
   port it is on. Authoritative: both ends agreed to advertise.
2. **Operator-declared links** — what a human asserted. Equally authoritative,
   and the whole point of the feature: a lot of lab gear (unmanaged switches,
   media converters, PDUs, older APs) speaks no LLDP at all and would otherwise
   be invisible.
3. **MAC-table inference** — a switch port that has learned exactly ONE MAC is
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
from typing import Any, Dict, List, Optional

from nw_topology_macs import classify_ports, is_topology_mac, norm_mac


#: Edge provenance, most trusted first. Used to decide which edge wins when two
#: sources describe the same link.
SOURCE_RANK = {"manual": 0, "lldp": 1, "mac": 2}


def _s(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _key_candidates(rec: Dict[str, Any]) -> List[str]:
    """Identity keys for one record, strongest first.

    A device shows up under different names depending on who is describing it,
    so each record contributes every identifier it knows and the alias table
    below unions them. Order matters: the first candidate becomes the node's
    canonical id, so a real fleet id always beats a MAC, which beats an IP,
    which beats a name.
    """
    out = []
    did = _s(rec.get("id"))
    if did:
        out.append("dev:" + did)
    for field in ("chassis", "mac", "base_mac", "remote_chassis"):
        mac = norm_mac(_s(rec.get(field)))
        if mac and is_topology_mac(mac):
            out.append("mac:" + mac)
    for field in ("address", "ip", "primary_ip", "remote_mgmt_ip", "mgmt_ip"):
        ip = _s(rec.get(field)).split("/")[0]
        if ip:
            out.append("ip:" + ip)
    for field in ("name", "remote_name", "hostname"):
        name = _s(rec.get(field))
        if name:
            out.append("name:" + name.casefold())
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
        self._parent: Dict[str, str] = {}

    def find(self, key: str) -> str:
        self._parent.setdefault(key, key)
        root = key
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[key] != root:  # path compression
            self._parent[key], key = root, self._parent[key]
        return root

    def union(self, keys: List[str]) -> str:
        """Merge every key into one set and return its root. The FIRST key wins
        as the root so a strong identifier (a fleet id) stays canonical rather
        than being replaced by whichever alias happened to be seen first."""
        keys = [k for k in keys if k]
        if not keys:
            return ""
        root = self.find(keys[0])
        for other in keys[1:]:
            other_root = self.find(other)
            if other_root != root:
                self._parent[other_root] = root
        return root


class TopologyBuilder:
    """Accumulates nodes and edges, then renders a graph."""

    def __init__(self, trunk_threshold: int = 4):
        self.trunk_threshold = trunk_threshold
        self.aliases = _Aliases()
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._edges: Dict[tuple, Dict[str, Any]] = {}
        self._trunks: List[Dict[str, Any]] = []

    # ── nodes ────────────────────────────────────────────────────────────────
    def add_node(self, rec: Dict[str, Any], kind: str, source: str) -> str:
        """Register (or enrich) a node and return its canonical id.

        Returns "" for a record carrying no usable identifier at all, which the
        callers treat as "nothing to draw" rather than inventing a node.
        """
        keys = _key_candidates(rec)
        if not keys:
            return ""
        # Any node already filed under one of these keys BEFORE the union. The
        # union can re-root the set (a stronger identifier arriving later wins),
        # which would otherwise orphan the node stored under the old root and
        # silently split one device into two -- exactly the phantom-device
        # failure this class exists to prevent.
        prior = []
        for key in keys:
            old_root = self.aliases.find(key)
            if old_root in self._nodes and self._nodes[old_root] not in prior:
                prior.append(self._nodes[old_root])
            self._nodes.pop(old_root, None)
        root = self.aliases.union(keys)

        node = None
        for existing in prior:
            if node is None:
                node = existing
                node["id"] = root
            else:
                _merge_node(node, existing)
        if node is None:
            node = {"id": root, "name": "", "kind": kind, "sources": [],
                    "addresses": [], "macs": [], "device_id": "", "tenant_id": "",
                    "object_type": "", "model": "", "site": "", "role": "",
                    "lldp_capable": False, "manual": False}
        self._nodes[root] = node
        # Edges already drawn against a merged-away id must follow the node.
        self._repoint_edges({e["id"] for e in prior if e["id"] != root}, root)
        if source not in node["sources"]:
            node["sources"].append(source)
        # A more specific kind wins: "switch" learned from the fleet should not
        # be flattened back to "endpoint" by a later MAC-table sighting.
        if _KIND_RANK.get(kind, 99) < _KIND_RANK.get(node["kind"], 99):
            node["kind"] = kind
        if not node["name"]:
            node["name"] = (_s(rec.get("name")) or _s(rec.get("remote_name"))
                            or _s(rec.get("hostname")))
        if not node["device_id"] and _s(rec.get("id")):
            node["device_id"] = _s(rec.get("id"))
        for field in ("tenant_id", "object_type", "model", "site", "role"):
            if not node[field] and _s(rec.get(field)):
                node[field] = _s(rec.get(field))
        for field in ("address", "ip", "primary_ip", "remote_mgmt_ip", "mgmt_ip"):
            ip = _s(rec.get(field)).split("/")[0]
            if ip and ip not in node["addresses"]:
                node["addresses"].append(ip)
        for field in ("chassis", "mac", "base_mac", "remote_chassis"):
            mac = norm_mac(_s(rec.get(field)))
            if mac and is_topology_mac(mac) and mac not in node["macs"]:
                node["macs"].append(mac)
        if rec.get("manual"):
            node["manual"] = True
        return root

    def resolve(self, rec: Dict[str, Any]) -> str:
        """Canonical id for a record WITHOUT creating a node.

        Used by MAC inference: a MAC we have never otherwise heard of should
        not by itself conjure a device onto the map — it becomes an endpoint
        only if the caller decides to add one.
        """
        for key in _key_candidates(rec):
            root = self.aliases.find(key)
            if root in self._nodes:
                return root
        return ""

    def _repoint_edges(self, old_ids: set, new_root: str) -> None:
        """Move edges off ids that were just merged away.

        A link can be drawn before the node it lands on gains a stronger
        identifier, so rewriting the node alone would leave the edge pointing at
        an id no longer present in ``nodes`` — an invisible link in the UI.
        """
        if not old_ids:
            return
        stale = [e for e in self._edges.values()
                 if e["a"] in old_ids or e["b"] in old_ids]
        if not stale:
            return
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
        if not a_id or not b_id or a_id == b_id:
            return
        ends = sorted([(a_id, _s(a_port)), (b_id, _s(b_port))])
        key = (ends[0][0], ends[0][1], ends[1][0], ends[1][1])
        edge = {
            "source": source, "detail": detail,
            "a": ends[0][0], "a_port": ends[0][1],
            "b": ends[1][0], "b_port": ends[1][1],
        }
        existing = self._edges.get(key)
        if existing is None:
            self._edges[key] = edge
            return
        # Keep the most trusted description of the same link.
        if SOURCE_RANK.get(source, 99) < SOURCE_RANK.get(existing["source"], 99):
            self._edges[key] = edge

    def has_link_on_port(self, node_id: str, port: str) -> bool:
        """Whether a trusted (non-inferred) link already occupies this port.

        MAC inference must not second-guess LLDP: if a port already has an LLDP
        or declared link, a single MAC learned there is that same neighbour, not
        an extra device hanging off it.
        """
        port = _s(port)
        for edge in self._edges.values():
            if edge["source"] == "mac":
                continue
            if (edge["a"] == node_id and edge["a_port"] == port) or \
               (edge["b"] == node_id and edge["b_port"] == port):
                return True
        return False

    def add_trunk(self, node_id: str, port: str, count: int) -> None:
        self._trunks.append({"node": node_id, "port": _s(port), "mac_count": count})

    # ── output ───────────────────────────────────────────────────────────────
    def render(self) -> Dict[str, Any]:
        nodes = sorted(self._nodes.values(), key=lambda n: (n["kind"], n["name"], n["id"]))
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
    if _KIND_RANK.get(src["kind"], 99) < _KIND_RANK.get(dst["kind"], 99):
        dst["kind"] = src["kind"]
    for field in ("name", "device_id", "tenant_id", "object_type", "model",
                  "site", "role"):
        if not dst[field] and src[field]:
            dst[field] = src[field]
    for field in ("sources", "addresses", "macs"):
        for value in src[field]:
            if value not in dst[field]:
                dst[field].append(value)
    dst["lldp_capable"] = dst["lldp_capable"] or src["lldp_capable"]
    dst["manual"] = dst["manual"] or src["manual"]

#: nw ``object_type`` → topology node kind.
_OBJECT_KIND = {"aos_switch": "switch", "cx_switch": "switch",
                "ex_switch": "switch", "gateway": "gateway"}


def build_topology(fleet: Optional[List[dict]] = None,
                   lldp_by_device: Optional[Dict[str, list]] = None,
                   macs_by_device: Optional[Dict[str, list]] = None,
                   netbox_devices: Optional[List[dict]] = None,
                   manual_devices: Optional[List[dict]] = None,
                   manual_links: Optional[List[dict]] = None,
                   trunk_threshold: int = 4,
                   infer_from_macs: bool = True) -> Dict[str, Any]:
    """Assemble the graph.

    ``fleet``           nw device records (id/name/object_type/address/tenant_id)
    ``lldp_by_device``  device id → NW_GET_LLDP_NEIGHBORS rows
    ``macs_by_device``  device id → NW_GET_MAC_TABLE rows
    ``netbox_devices``  NetBox inventory rows (name/primary_ip/role/site/model)
    ``manual_devices``  operator-declared devices that speak no LLDP
    ``manual_links``    operator-declared links

    Ordering is deliberate. Inventory first so that by the time MAC inference
    runs, as many MACs as possible already resolve to a NAMED device; then LLDP,
    so declared and inferred links can both see which ports are already spoken
    for; then inference last, filling only the gaps.
    """
    builder = TopologyBuilder(trunk_threshold=trunk_threshold)

    # ── 1. Inventory: the nw fleet ──────────────────────────────────────────
    fleet_ids: Dict[str, str] = {}
    for dev in (fleet or []):
        if not isinstance(dev, dict):
            continue
        kind = _OBJECT_KIND.get(_s(dev.get("object_type")), "device")
        node_id = builder.add_node(dev, kind, "fleet")
        if node_id:
            fleet_ids[_s(dev.get("id"))] = node_id

    # ── 2. Inventory: NetBox ────────────────────────────────────────────────
    # NetBox knows about hardware the nw fleet has never logged into, which is
    # most of what an operator wants on a topology map. It contributes nodes and
    # identity (name ⇄ IP), never links: NetBox cables are not modelled here.
    for dev in (netbox_devices or []):
        if not isinstance(dev, dict):
            continue
        builder.add_node(dev, "device", "netbox")

    # ── 3. Operator-declared devices (the no-LLDP case) ─────────────────────
    for dev in (manual_devices or []):
        if not isinstance(dev, dict):
            continue
        rec = dict(dev)
        rec["manual"] = True
        builder.add_node(rec, _s(dev.get("kind")) or "manual", "manual")

    # ── 4. LLDP adjacencies ─────────────────────────────────────────────────
    for device_id, rows in (lldp_by_device or {}).items():
        local_id = fleet_ids.get(_s(device_id)) or builder.resolve({"id": device_id})
        if not local_id:
            continue
        if rows:
            builder._nodes[local_id]["lldp_capable"] = True
        for row in (rows or []):
            if not isinstance(row, dict):
                continue
            neighbour = {
                "remote_chassis": row.get("remote_chassis"),
                "remote_name": row.get("remote_name"),
                "remote_mgmt_ip": row.get("remote_mgmt_ip"),
            }
            remote_id = builder.add_node(neighbour, "neighbor", "lldp")
            if not remote_id:
                continue
            builder._nodes[remote_id]["lldp_capable"] = True
            builder.add_edge(local_id, row.get("local_port"),
                             remote_id, row.get("remote_port"),
                             "lldp", _s(row.get("remote_descr")))

    # ── 5. Operator-declared links ──────────────────────────────────────────
    # Declared BEFORE inference so a human assertion always occupies the port
    # and inference cannot contradict it.
    for link in (manual_links or []):
        if not isinstance(link, dict):
            continue
        a_id = builder.resolve({"id": link.get("a"), "name": link.get("a"),
                                "mac": link.get("a"), "ip": link.get("a")})
        b_id = builder.resolve({"id": link.get("b"), "name": link.get("b"),
                                "mac": link.get("b"), "ip": link.get("b")})
        if not a_id or not b_id:
            continue
        builder.add_edge(a_id, link.get("a_port"), b_id, link.get("b_port"),
                         "manual", _s(link.get("note")))

    # ── 6. MAC-table inference ──────────────────────────────────────────────
    if infer_from_macs:
        for device_id, rows in (macs_by_device or {}).items():
            local_id = fleet_ids.get(_s(device_id))
            if not local_id:
                continue
            for port, info in classify_ports(rows or [],
                                             trunk_threshold=trunk_threshold).items():
                if info["kind"] == "access":
                    if builder.has_link_on_port(local_id, port):
                        continue  # LLDP or an operator already described it
                    mac = info["macs"][0]
                    remote_id = builder.resolve({"mac": mac})
                    if not remote_id:
                        continue  # an unknown MAC is not yet a device
                    builder.add_edge(local_id, port, remote_id, "",
                                     "mac", "single MAC learned on port")
                else:
                    # 2+ MACs: an uplink or a downstream segment. It says
                    # nothing about what is DIRECTLY attached, so it is
                    # reported for the UI to offer "declare what is here"
                    # rather than guessed at.
                    builder.add_trunk(local_id, port, info["count"])

    return builder.render()
