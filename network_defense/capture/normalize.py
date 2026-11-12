from __future__ import annotations

from network_defense.models import PacketEvent, utc_now


def normalize_packet(packet: object) -> PacketEvent | None:
    """Map a Scapy packet to a stable, payload-free event schema."""
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    if not packet.haslayer(IP) and not packet.haslayer(IPv6):
        return None
    ip = packet[IP] if packet.haslayer(IP) else packet[IPv6]
    protocol, sport, dport, flags = "OTHER", None, None, None
    if packet.haslayer(TCP):
        layer = packet[TCP]
        protocol, sport, dport, flags = "TCP", int(layer.sport), int(layer.dport), str(layer.flags)
    elif packet.haslayer(UDP):
        layer = packet[UDP]
        protocol, sport, dport = "UDP", int(layer.sport), int(layer.dport)

    query = None
    if packet.haslayer(DNS) and packet.haslayer(DNSQR) and packet[DNS].qr == 0:
        # DNS names are ASCII on the wire (including punycode).  Do not let a
        # malformed name terminate live capture; retaining punycode is fine for
        # this metadata-only prototype.
        query = packet[DNSQR].qname.decode("ascii", errors="replace").rstrip(".")
    return PacketEvent(
        timestamp=utc_now(), src_ip=str(ip.src), dst_ip=str(ip.dst), src_port=sport,
        dst_port=dport, protocol=protocol, length=len(packet), tcp_flags=flags, dns_query=query,
    )
