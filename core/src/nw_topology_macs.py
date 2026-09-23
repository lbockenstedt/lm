"""MAC-address classification for the topology builder.

Split out from ``nw_topology`` because these are the rules most likely to need
tuning against real hardware, and they are pure string/set work that can be
exercised without building a graph at all.
"""
import re


def norm_mac(mac) -> str:
    """Canonical lower-colon form, or the stripped input when it is not a MAC.

    Every source spells MACs differently -- AOS-S emits six space-separated
    octets, ArubaOS dotted triplets, NetBox colons -- and an LLDP chassis id
    must compare equal to the same address in a MAC table or the two views
    describe two different nodes.
    """
    raw = "" if mac is None else str(mac).strip()
    if not raw:
        return ""
    hex_only = re.sub(r"[^0-9A-Fa-f]", "", raw)
    if len(hex_only) != 12:
        return raw
    return ":".join(hex_only[i:i + 2] for i in range(0, 12, 2)).lower()


def is_topology_mac(mac: str) -> bool:
    if not mac:
        return False
    mac = re.sub(r'[^0-9a-fA-F]', '', mac)
    if len(mac) != 12:
        return False
    try:
        mac_bytes = [int(mac[i:i+2], 16) for i in range(0, 12, 2)]
    except ValueError:
        return False
    mac_str = ':'.join(f'{b:02x}' for b in mac_bytes)
    if mac_str == '00:00:00:00:00:00':
        return False
    if mac_str == 'ff:ff:ff:ff:ff:ff':
        return False
    if mac_bytes[0] & 1:
        return False
    if mac_bytes[:3] == [0x01, 0x80, 0xc2]:
        return False
    if mac_bytes[:3] == [0x01, 0x00, 0x5e]:
        return False
    if mac_bytes[:2] == [0x33, 0x33]:
        return False
    return True

def classify_ports(mac_rows: list, trunk_threshold: int = 4) -> dict:
    result = {}
    for row in mac_rows:
        if not isinstance(row, dict):
            continue
        mac = row.get('mac')
        interface = '' if row.get('interface') is None else str(row.get('interface')).strip()
        # "local" is the switch's own CPU/management port, not a link to
        # anywhere. Real fleet data is full of it: the ArubaOS gateway reports
        # most of its forwarding table against "local".
        if not is_topology_mac(mac) or not interface or interface.lower() == 'local':
            continue
        if interface not in result:
            result[interface] = {'macs': set(), 'count': 0, 'kind': ''}
        result[interface]['macs'].add(norm_mac(mac))
    for interface, data in result.items():
        macs_list = sorted(list(data['macs']))
        count = len(macs_list)
        if count == 1:
            kind = 'access'
        elif count >= trunk_threshold:
            kind = 'trunk'
        else:
            kind = 'multi'
        result[interface] = {
            'macs': macs_list,
            'count': count,
            'kind': kind
        }
    return {k: v for k, v in result.items() if v['count'] > 0}