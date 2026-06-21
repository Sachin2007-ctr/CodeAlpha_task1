#!/usr/bin/env python3
"""
Task 1: Basic Network Sniffer
CodeAlpha Cybersecurity Internship
Description: Captures and analyzes network traffic packets
"""

import socket
import struct
import textwrap

# ─────────────────────────────────────────────
# HELPER FORMATTERS
# ─────────────────────────────────────────────

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


def ipv4(addr):
    return '.'.join(map(str, addr))


# ─────────────────────────────────────────────
# PACKET PARSERS
# ─────────────────────────────────────────────

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack(
        '! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return (src_port, dest_port, sequence, acknowledgement,
            flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:])


def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


# ─────────────────────────────────────────────
# MAIN SNIFFER
# ─────────────────────────────────────────────

def sniff(packet_count=20):
    """
    Sniff network packets using a raw socket.
    Requires root/administrator privileges.
    """
    print("=" * 60)
    print("  CodeAlpha — Basic Network Sniffer")
    print("  Task 1 | Cybersecurity Internship")
    print("=" * 60)
    print(f"[*] Capturing {packet_count} packets...\n")

    # AF_PACKET / SOCK_RAW captures all Ethernet frames (Linux only)
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print("[!] Permission denied. Please run as root: sudo python3 task1_network_sniffer.py")
        return
    except AttributeError:
        print("[!] AF_PACKET not supported on this OS (Linux only). Use Scapy on Windows/macOS.")
        return

    captured = 0
    while captured < packet_count:
        raw_data, addr = conn.recvfrom(65536)
        captured += 1

        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print(f"\n{'─'*60}")
        print(f"  Packet #{captured}")
        print(f"  Ethernet Frame:")
        print(f"    Destination : {dest_mac}")
        print(f"    Source      : {src_mac}")
        print(f"    Protocol    : {eth_proto}")

        # IPv4
        if eth_proto == 8:
            (version, header_len, ttl, proto,
             src_ip, target_ip, ipv4_data) = ipv4_packet(data)

            print(f"\n  IPv4 Packet:")
            print(f"    Version     : {version}")
            print(f"    Header Len  : {header_len}")
            print(f"    TTL         : {ttl}")
            print(f"    Source IP   : {src_ip}")
            print(f"    Destination : {target_ip}")

            # ICMP
            if proto == 1:
                icmp_type, code, checksum, icmp_data = icmp_packet(ipv4_data)
                print(f"\n  ICMP Packet:")
                print(f"    Type     : {icmp_type}  Code     : {code}")
                print(f"    Checksum : {checksum}")
                print(f"    Data:\n{format_multi_line('      ', icmp_data)}")

            # TCP
            elif proto == 6:
                (src_port, dest_port, seq, ack,
                 urg, ack_f, psh, rst, syn, fin, tcp_data) = tcp_segment(ipv4_data)
                print(f"\n  TCP Segment:")
                print(f"    Src Port : {src_port}   Dst Port : {dest_port}")
                print(f"    Sequence : {seq}")
                print(f"    Flags    → URG:{urg} ACK:{ack_f} PSH:{psh} RST:{rst} SYN:{syn} FIN:{fin}")
                if tcp_data:
                    print(f"    Data:\n{format_multi_line('      ', tcp_data)}")

            # UDP
            elif proto == 17:
                src_port, dest_port, size, udp_data = udp_segment(ipv4_data)
                print(f"\n  UDP Segment:")
                print(f"    Src Port : {src_port}   Dst Port : {dest_port}   Size: {size}")
                if udp_data:
                    print(f"    Data:\n{format_multi_line('      ', udp_data)}")

            else:
                print(f"\n  Other IPv4 Data:\n{format_multi_line('    ', ipv4_data)}")

        else:
            print(f"\n  Non-IPv4 Data:\n{format_multi_line('    ', data)}")

    print(f"\n{'='*60}")
    print(f"  [✓] Captured {captured} packets successfully.")
    print("=" * 60)


if __name__ == "__main__":
    sniff(packet_count=20)
