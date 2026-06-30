"""Server-side tenant-subnet filter — shared across modules.

Pure functions (no I/O). Ports the proven client-side filter in
``WebUI/main.js`` (``itemInTenantPrefixes`` / ``firewallRuleInTenantPrefixes``)
to Python so the hub can enforce per-tenant subnet isolation at the API layer:
a tenant cannot retrieve another tenant's subnet data even by calling the API
directly (the client-side filter is responsive UX only and is bypassable).

A tenant's allowed prefixes come from NetBox (resolved in ``api.py`` via
``_resolve_prefixes``). Semantics mirror the client exactly:

  - **empty prefix list → show all** (tenant unconfigured / admin / module
    disabled — there is nothing to filter against).
  - For each item, look at the configured IP fields. From a field value,
    extract concrete IPv4/CIDR strings. Non-IP values (alias names, ``any``,
    ``*``, empty) contribute no addresses → that field is skipped.
  - If any extracted address falls inside a tenant prefix → show the item.
  - If at least one field had concrete IPs but none matched → hide.
  - If no field yielded any concrete IP → hide (the record can't be attributed
    to a tenant; err on hiding so an unattributable record — a stopped VM, an
    empty DHCP/alias row — never leaks across tenants). ``drop_no_ip=False``
    restores the legacy "can't filter → show" behavior.

Firewall rules use ``firewall_rule_in_prefixes``: a rule is shown when EITHER
side carries an address that belongs to the tenant — a concrete IP/CIDR inside
one of the tenant's prefixes, OR a reference to one of the tenant's own aliases
(an alias whose OPNsense ``category`` field equals the tenant's display name,
or whose resolved networks overlap a tenant prefix). A wildcard (``any``/``*``)
on a side contributes no address for that side (it is simply skipped); it does
not by itself drop the rule — the other side can still qualify it. A rule with
no tenant address on either side (e.g. ``any → any``, or both sides off-prefix
and not the tenant's aliases) is dropped.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable, List, Optional, Sequence

# Concrete IPv4 or IPv4/CIDR strings embedded in a field value. Anything that
# doesn't match (alias names like "LAN_NET", "any", "RFC1918", empty) yields no
# hits → the caller treats the field as non-IP and skips it.
_ADDR_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b")

# Values that mean "no concrete address" — pass the field through (can't filter).
_NON_IP = {"", "any", "*", "—", "-"}


def _parse_network(cidr: str) -> Optional[ipaddress._BaseNetwork]:
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None


def extract_addrs(val: Any) -> Optional[List[str]]:
    """Concrete IPv4/CIDR strings in ``val``, or ``None`` if it is non-IP.

    ``None`` (not an empty list) signals "alias / wildcard / empty" so the
    caller can distinguish "field had addresses, none matched" from "field had
    no addresses to test". Mirrors ``_extractAddrs`` (main.js:363).
    """
    if val is None:
        return None
    s = str(val).strip()
    if s.lower() in _NON_IP or s in _NON_IP:
        return None
    hits = _ADDR_RE.findall(s)
    return hits or None


def _addr_in_prefixes(addr: str, nets: Sequence[ipaddress._BaseNetwork]) -> bool:
    """True if ``addr`` (bare IP or CIDR) overlaps/touches any tenant net.

    Mirrors ``_addrInPrefixes`` (main.js:371): a CIDR item overlaps a prefix;
    a bare IP is contained in a prefix.
    """
    if not nets:
        return False
    if "/" in addr:
        a = _parse_network(addr)
        if a is None:
            return False
        return any(a.overlaps(n) for n in nets)
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in n for n in nets)


def _nets(prefixes: Iterable[str]) -> List[ipaddress._BaseNetwork]:
    out: List[ipaddress._BaseNetwork] = []
    for p in prefixes:
        n = _parse_network(p)
        if n is not None:
            out.append(n)
    return out


def _find_list_slot(data: Any):
    """Locate the record list inside a spoke response envelope.

    Mirrors the client ``extractItems`` (main.js:3899): bare list, then
    ``data['data']``, ``data['payload']['data']``, ``data['rows']``, then the
    first list-of-dicts value. Returns ``(container, key)`` where
    ``container[key]`` is the list to mutate, or ``(None, None)``. For a bare
    list the container is the list itself and ``key`` is ``None`` (filter
    in place).
    """
    if isinstance(data, list):
        return (data, None)
    if isinstance(data, dict):
        v = data.get("data")
        if isinstance(v, list):
            return (data, "data")
        payload = data.get("payload")
        if isinstance(payload, dict) and isinstance(payload.get("data"), list):
            return (payload, "data")
        if isinstance(data.get("rows"), list):
            return (data, "rows")
        for k, v in data.items():
            if isinstance(v, list) and v and isinstance(v[0], dict):
                return (data, k)
    return (None, None)


def _filter_list(lst: list, keep) -> list:
    out: list = []
    for item in lst:
        if not isinstance(item, dict):
            out.append(item)
            continue
        if keep(item):
            out.append(item)
    return out


def filter_items_by_prefixes(
    items: Any, prefixes: Sequence[str], ip_fields: Sequence[str],
    drop_no_ip: bool = True, tenant_category: Optional[str] = None,
    category_field: str = "category",
) -> Any:
    """Drop items whose concrete IPs all fall outside ``prefixes``.

    Mirrors ``itemInTenantPrefixes`` (main.js:389). ``items`` may be a bare list
    or a spoke envelope dict; the record list is located via
    ``_find_list_slot`` and filtered in place. Anything without a record list
    is returned unchanged.

    An item that yields no concrete IP from any field is **dropped** by default
    (``drop_no_ip=True``): it can't be attributed to a tenant, so erring on
    hiding keeps unattributable records (stopped VMs, empty DHCP/alias rows)
    from leaking across tenants. Pass ``drop_no_ip=False`` to restore the
    legacy "can't filter → show" behavior.

    ``tenant_category`` (the tenant's display name) enables an alternate
    attribution path for modules whose records carry an OPNsense ``category``
    config field: an item whose ``category_field`` equals ``tenant_category`` is
    kept regardless of its IPs (the admin explicitly tagged it to this tenant).
    Only pass ``tenant_category`` for modules that use categories (rules/nat/
    aliases); ``None`` (default) disables the check.
    """
    if not prefixes:
        return items
    nets = _nets(prefixes)
    if not nets:
        return items

    def keep(item: dict) -> bool:
        if tenant_category and str(item.get(category_field) or "").strip() == tenant_category:
            return True  # explicitly attributed to this tenant via category
        has_concrete = False
        for f in ip_fields:
            addrs = extract_addrs(item.get(f))
            if addrs is None:
                continue  # alias / 'any' — skip this field
            has_concrete = True
            if any(_addr_in_prefixes(a, nets) for a in addrs):
                return True
        if has_concrete:
            return False  # concrete IPs but none matched → drop
        return not drop_no_ip  # no concrete IP → drop by default (err on hiding)

    container, key = _find_list_slot(items)
    if container is None:
        return items
    filtered = _filter_list(container if key is None else container[key], keep)
    if key is None:
        # bare list — return the filtered copy
        return filtered
    container[key] = filtered
    return items


def filter_firewall_rules(data: Any, prefixes: Sequence[str], alias_map: Any = None,
                          tenant_category: Optional[str] = None,
                          category_field: str = "category") -> Any:
    """Strict firewall-rule filter applied to the record list inside a spoke
    envelope. Locates the list via ``_find_list_slot`` and keeps each rule for
    which ``firewall_rule_in_prefixes`` is True. Empty prefixes → unchanged.

    ``alias_map`` (from ``build_alias_map``) lets the matcher resolve OPNsense
    alias names in a rule's source/destination to concrete networks before
    matching tenant prefixes; ``None`` → concrete-IP-only behavior (legacy).

    ``tenant_category`` (tenant display name) adds an OR attribution path: a
    rule whose ``category_field`` equals ``tenant_category`` is kept regardless
    of its source/destination (the admin explicitly tagged it to this tenant).
    ``None`` (default) disables the category check.
    """
    if not prefixes:
        return data
    nets = _nets(prefixes)
    if not nets:
        return data
    container, key = _find_list_slot(data)
    if container is None:
        return data
    filtered = _filter_list(
        container if key is None else container[key],
        lambda r: firewall_rule_in_prefixes(r, prefixes, alias_map,
                                             tenant_category=tenant_category,
                                             category_field=category_field),
    )
    if key is None:
        return filtered
    container[key] = filtered
    return data


def filter_record_by_prefixes(record: Any, prefixes: Sequence[str], ip_fields: Sequence[str],
                              drop_no_ip: bool = True):
    """Single-record gate: return ``record`` if it should be shown, else ``None``.

    Same semantics as ``filter_items_by_prefixes`` applied to one item — used to
    gate drill-down endpoints that return a single record (e.g. CPPM
    device-enrich) rather than a list. A record with no concrete IP is dropped
    by default (``drop_no_ip=True``); pass ``False`` for the legacy keep behavior.
    """
    if not prefixes or not isinstance(record, dict):
        return record
    nets = _nets(prefixes)
    if not nets:
        return record
    has_concrete = False
    for f in ip_fields:
        addrs = extract_addrs(record.get(f))
        if addrs is None:
            continue
        has_concrete = True
        if any(_addr_in_prefixes(a, nets) for a in addrs):
            return record
    if has_concrete:
        return None  # concrete IPs but none matched → drop
    return None if drop_no_ip else record  # no concrete IP → drop by default


def _is_wildcard(val: Any) -> bool:
    """True when a firewall source/destination means "any address"."""
    if val is None:
        return True
    s = str(val).strip().lower()
    if not s or s in ("any", "*"):
        return True
    if s == "0.0.0.0/0":
        return True
    return bool(re.match(r"^any(:\S+)?$", s))


def build_alias_map(aliases: Any) -> Dict[str, "dict"]:
    """Build ``{alias_name_lower: {"nets": [concrete CIDR/IP strings], "category": str}}``
    from the OPNsense spoke alias list (``OPNSENSE_GET_ALIASES`` →
    ``[{name, type, content, category}, ...]``).

    Each alias ``content`` is split on whitespace/newlines/commas. Tokens that
    are concrete IPv4/CIDR (matching ``_ADDR_RE``) are kept directly; other tokens
    are treated as nested alias names and resolved recursively (cycle-guarded via
    a ``visited`` set). Aliases that resolve to no concrete networks (mac/url
    tables, empty content, unresolved nested names) map to ``{"nets": [], ...}`` —
    present in the map (so the matcher knows the name *is* a known alias and can
    read its ``category``) but with nothing to overlap. The map is keyed by
    lowercased name; lookup is case-insensitive. ``category`` is the alias's
    OPNsense category verbatim (``""`` when absent) — the firewall matcher uses it
    to decide whether an alias belongs to a given tenant.
    """
    raw: Dict[str, str] = {}
    cat: Dict[str, str] = {}
    if isinstance(aliases, list):
        for a in aliases:
            if not isinstance(a, dict):
                continue
            name = str(a.get("name") or "").strip()
            if not name:
                continue
            raw[name.lower()] = str(a.get("content") or "")
            cat[name.lower()] = str(a.get("category") or "").strip()

    def resolve(name_lower: str, visited: set) -> List[str]:
        if name_lower in visited:
            return []
        visited.add(name_lower)
        out: List[str] = []
        content = raw.get(name_lower)
        if not content:
            return out
        for tok in re.split(r"[\s,]+", content.strip()):
            if not tok:
                continue
            hits = _ADDR_RE.findall(tok)
            if hits:
                out.extend(hits)
                continue
            tok_l = tok.lower()
            if tok_l in raw:
                out.extend(resolve(tok_l, visited))
        return out

    return {name: {"nets": resolve(name, set()), "category": cat.get(name, "")}
            for name in raw}


# Strip a trailing ``:port`` so values like ``LAN_net:443`` / ``10.0.5.0/24:443``
# resolve their address part. A port is all-digits, ``any``, or a port range/list.
_PORT_SUFFIX = re.compile(r":(?:\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*|any)$")


def _alias_entry(alias_map: Any, name_lower: str) -> Optional[dict]:
    """Look up an alias by lowercased name in ``alias_map`` (whole-token first,
    then any whitespace/comma-separated token). Returns the ``{nets, category}``
    entry or ``None`` when the name isn't a known alias."""
    if not isinstance(alias_map, dict):
        return None
    e = alias_map.get(name_lower)
    if e is not None:
        return e
    for tok in re.split(r"[\s,]+", name_lower):
        if tok and tok in alias_map:
            return alias_map[tok]
    return None


def _side_qualifies(val: Any, nets: Sequence[ipaddress._BaseNetwork],
                    alias_map: Any, tenant_category: Optional[str]) -> bool:
    """True when a firewall source/destination value belongs to the tenant.

    A side belongs to the tenant when it carries a concrete IP/CIDR inside one of
    the tenant's prefixes, OR it references a known alias that is the tenant's
    (the alias's ``category`` equals ``tenant_category``) or whose resolved
    networks overlap a tenant prefix. A wildcard (``any``/``*``), an unknown
    interface/alias name, or an off-prefix concrete IP all yield ``False`` — the
    side simply contributes nothing; the *other* side can still qualify the rule.
    """
    if val is None:
        return False
    s = str(val).strip()
    if _is_wildcard(s):
        return False  # wildcard → no address on this side (other side may qualify)
    addr_part = _PORT_SUFFIX.sub("", s).strip()
    if not addr_part or _is_wildcard(addr_part):
        return False
    # Inline concrete IPs/CIDRs anywhere in the address part → check prefixes.
    inline = _ADDR_RE.findall(addr_part)
    if inline and any(_addr_in_prefixes(a, nets) for a in inline):
        return True
    # Alias reference (whole token, then whitespace/comma-split tokens).
    e = _alias_entry(alias_map, addr_part.lower())
    if e is not None:
        # Tenant-owned alias (category attribution) → qualifies on its own.
        if tenant_category and e.get("category") == tenant_category:
            return True
        # Alias resolved to networks overlapping a tenant prefix → qualifies.
        for a in e.get("nets") or []:
            if _addr_in_prefixes(a, nets):
                return True
    return False


def firewall_rule_in_prefixes(rule: Any, prefixes: Sequence[str], alias_map: Any = None,
                              tenant_category: Optional[str] = None,
                              category_field: str = "category") -> bool:
    """Firewall-rule tenant-prefix check (with OPNsense alias + category resolution).

    A rule is shown to a tenant when EITHER side carries an address that belongs
    to that tenant:

      - a concrete IP/CIDR inside one of the tenant's prefixes, or
      - a reference to one of the tenant's own aliases — an alias whose OPNsense
        ``category`` equals ``tenant_category`` (the tenant's display name), or
        whose resolved networks overlap a tenant prefix.

    A wildcard (``any``/``*``) on a side contributes no address for that side; it
    does not by itself drop the rule (the other side may still qualify it). So
    ``any → <tenant-ip>`` shows (destination is in the tenant's subnet), while
    ``any → any`` drops (neither side belongs to the tenant).

    ``alias_map`` (from ``build_alias_map``) resolves alias names to networks and
    exposes each alias's ``category``; ``None`` → concrete-IP-only behavior.

    ``tenant_category`` (tenant display name) is also an OR attribution path on
    the rule itself: a rule whose own ``category_field`` equals it is shown
    regardless of source/destination (explicitly tagged to this tenant by the
    admin — the escape hatch). ``None`` disables both the alias-category and
    rule-category checks.
    """
    if not prefixes:
        return True
    if not isinstance(rule, dict):
        return True
    if tenant_category and str(rule.get(category_field) or "").strip() == tenant_category:
        return True  # rule explicitly attributed to this tenant via its category
    nets = _nets(prefixes)
    if not nets:
        return True
    src_raw = rule.get("source")
    dst_raw = rule.get("destination")
    # Either side belonging to the tenant → show; otherwise drop.
    if _side_qualifies(src_raw, nets, alias_map, tenant_category):
        return True
    if _side_qualifies(dst_raw, nets, alias_map, tenant_category):
        return True
    return False