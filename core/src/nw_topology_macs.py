"""MAC-address classification for the topology builder.

Split out from ``nw_topology`` because these are the rules most likely to need
tuning against real hardware, and they are pure string/set work that can be
exercised without building a graph at all.
"""
# re strips separators and checks MAC formats.
import re


def norm_mac(mac) -> str:
    """Canonical lower-colon form, or the stripped input when it is not a MAC.

    Every source spells MACs differently -- AOS-S emits six space-separated
    octets, ArubaOS dotted triplets, NetBox colons -- and an LLDP chassis id
    must compare equal to the same address in a MAC table or the two views
    describe two different nodes.
    """
    # Treat None as empty and trim whitespace.
    raw = "" if mac is None else str(mac).strip()
    if not raw:
        return ""
    # Keep only hex digits; anything not exactly 12 of them is returned unchanged.
    hex_only = re.sub(r"[^0-9A-Fa-f]", "", raw)
    if len(hex_only) != 12:
        return raw
    # Rebuild as six lower-case colon-separated octets.
    return ":".join(hex_only[i:i + 2] for i in range(0, 12, 2)).lower()


def is_topology_mac(mac: str) -> bool:
    """Return True when mac is a real unicast station MAC useful for topology.

    Rejects malformed values, all-zero, broadcast, multicast (including STP/LLDP and
    IPv4/IPv6 multicast ranges).
    """
    # Empty input is never a topology MAC.
    if not mac:
        return False
    # Strip separators; a MAC must be exactly 12 hex digits.
    mac = re.sub(r'[^0-9a-fA-F]', '', mac)
    if len(mac) != 12:
        return False
    # Parse into six byte values; non-hex characters make it invalid.
    try:
        mac_bytes = [int(mac[i:i+2], 16) for i in range(0, 12, 2)]
    except ValueError:
        return False
    # Canonical text form for the all-zero/broadcast checks.
    mac_str = ':'.join(f'{b:02x}' for b in mac_bytes)
    if mac_str == '00:00:00:00:00:00':
        return False
    if mac_str == 'ff:ff:ff:ff:ff:ff':
        return False
    # Low bit of the first octet set means a multicast/group address.
    if mac_bytes[0] & 1:
        return False
    # 01:80:c2 is the IEEE reserved block (STP, LLDP); 01:00:5e is IPv4 multicast.
    if mac_bytes[:3] == [0x01, 0x80, 0xc2]:
        return False
    if mac_bytes[:3] == [0x01, 0x00, 0x5e]:
        return False
    # 33:33 prefix is IPv6 multicast.
    if mac_bytes[:2] == [0x33, 0x33]:
        return False
    return True

def classify_ports(mac_rows: list, trunk_threshold: int = 4) -> dict:
    """Group MAC-table rows by interface and label each port by how many MACs it sees.

    One MAC is "access", at least trunk_threshold is "trunk", in between is "multi".
    Returns {interface: {"macs": sorted list, "count": n, "kind": label}}.
    """
    # interface -> {"macs": set, "count", "kind"} while collecting.
    result = {}
    # Collect the distinct station MACs seen on each interface.
    for row in mac_rows:
        # Skip malformed rows.
        if not isinstance(row, dict):
            continue
        # Read the MAC and the trimmed interface name.
        mac = row.get('mac')
        interface = '' if row.get('interface') is None else str(row.get('interface')).strip()
        # "local" is the switch's own CPU/management port, not a link to
        # anywhere. Real fleet data is full of it: the ArubaOS gateway reports
        # most of its forwarding table against "local".
        if not is_topology_mac(mac) or not interface or interface.lower() == 'local':
            continue
        # Start a bucket for a new interface, then add the normalized MAC.
        if interface not in result:
            result[interface] = {'macs': set(), 'count': 0, 'kind': ''}
        result[interface]['macs'].add(norm_mac(mac))
    # Classify each interface by its distinct MAC count.
    for interface, data in result.items():
        macs_list = sorted(list(data['macs']))
        count = len(macs_list)
        if count == 1:
            kind = 'access'
        elif count >= trunk_threshold:
            kind = 'trunk'
        else:
            kind = 'multi'
        # Replace the working bucket with the final sorted, labelled form.
        result[interface] = {
            'macs': macs_list,
            'count': count,
            'kind': kind
        }
    # Return only interfaces that saw at least one MAC.
    return {k: v for k, v in result.items() if v['count'] > 0}