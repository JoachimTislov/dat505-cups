#!/usr/bin/env python3
"""Detect suspicious CUPS discovery and IPP activity in a live capture or a PCAP.

Rules: unauthorized printer advertisements, IPP callbacks to advertised
printers, repeated discovery messages, and malformed or inconsistent protocol
fields. Alerts are exported as JSON or CSV.
"""
import argparse
import csv
import json
import logging
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urlsplit

from scapy.all import IP, TCP, UDP, rdpcap, sniff

LOG = logging.getLogger("cups_detector")
CUPS_PORT = 631
# Sliding window (seconds) for the repeated-discovery rule.
REPEAT_WINDOW = 60.0
# Legacy browse record: <type> <state> <uri> "location" "info".
BROWSE_RE = re.compile(
    r'^\s*(\d+)\s+(\d+)\s+(https?://\S+)\s+"([^"]*)"\s+"([^"]*)"\s*$'
)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Alert on suspicious CUPS printer-discovery traffic.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pcap", help="Offline PCAP to analyse")
    source.add_argument("--iface", help="Interface to monitor live")
    parser.add_argument("--count", type=int, default=0, help="Live mode: stop after N packets (0 = until interrupted)")
    parser.add_argument(
        "--allow",
        action="append",
        default=[],
        help="Printer address that is authorised. Repeat for more than one. Empty means every advertisement is unauthorised.",
    )
    parser.add_argument("--repeat-threshold", type=int, default=5)
    parser.add_argument("--format", choices=("json", "csv"), default="json")
    parser.add_argument("--output", default="evidence/alerts.json")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args(argv)


def alert(rule, packet, detail):
    src = packet[IP].src if packet.haslayer(IP) else ""
    dst = packet[IP].dst if packet.haslayer(IP) else ""
    return {
        "time": datetime.fromtimestamp(float(packet.time), tz=timezone.utc).isoformat(),
        "rule": rule,
        "src": src,
        "dst": dst,
        "summary": packet.summary(),
        "detail": detail,
    }


def parse_browse(payload):
    """Parse a legacy browse record, or return None if it is malformed.

    Returns the record fields with the URI split into host and port.
    """
    try:
        text = bytes(payload).decode("latin-1")
    except Exception:
        return None
    match = BROWSE_RE.match(text)
    if not match:
        return None
    uri = urlsplit(match.group(3))
    return {
        "type": int(match.group(1)),
        "state": int(match.group(2)),
        "uri": match.group(3),
        "host": uri.hostname,
        "port": uri.port or CUPS_PORT,
        "location": match.group(4),
        "info": match.group(5),
    }


def browse_payload(packet):
    """UDP payload of a browse datagram, or None."""
    if UDP not in packet or packet[UDP].dport != CUPS_PORT:
        return None
    payload = bytes(packet[UDP].payload)
    return payload or None


def remember_advertisement(packet, state):
    """Track hosts that have been advertised, for the IPP-callback rule."""
    payload = browse_payload(packet)
    if payload is None:
        return
    record = parse_browse(payload)
    if record and record["host"]:
        state.setdefault("advertised", set()).add(record["host"])


def unauthorized_advertisement(packet, allow):
    """Return an alert if this is a printer advertisement from outside --allow."""
    payload = browse_payload(packet)
    if payload is None:
        return None
    record = parse_browse(payload)
    if record is None:
        return None  # malformed records are handled by malformed_fields
    src = packet[IP].src
    if src in allow or record["host"] in allow:
        return None
    return alert(
        "unauthorized-advertisement",
        packet,
        "browse record for %s from non-allowlisted %s" % (record["uri"], src),
    )


def suspicious_ipp(packet, allow, state):
    """Return an alert if this TCP session looks like an unexpected IPP callback.

    A new (SYN, not SYN-ACK) TCP connection towards a host that was advertised
    in a browse record earlier in the capture, unless that host is allowlisted.
    """
    if TCP not in packet:
        return None
    tcp = packet[TCP]
    if not (tcp.flags.S and not tcp.flags.A):
        return None  # only flag new connections, not established traffic
    dst = packet[IP].dst
    if dst not in state.get("advertised", set()) or dst in allow:
        return None
    return alert(
        "ipp-callback",
        packet,
        "connection opened to advertised printer %s:%d" % (dst, tcp.dport),
    )


def repeated_discovery(packet, state, threshold):
    """Return an alert if the same source is advertising too often.

    Counts browse advertisements per source address inside a sliding
    REPEAT_WINDOW-second window; alerts once, when the threshold is crossed.
    """
    payload = browse_payload(packet)
    if payload is None:
        return None
    record = parse_browse(payload)
    if record is None:
        return None
    src = packet[IP].src
    timestamp = float(packet.time)
    times = [t for t in state["seen"].get(src, []) if timestamp - t <= REPEAT_WINDOW]
    times.append(timestamp)
    state["seen"][src] = times
    if len(times) == threshold + 1:
        return alert(
            "repeated-discovery",
            packet,
            "%d advertisements from %s in %.0fs (threshold %d)"
            % (len(times), src, REPEAT_WINDOW, threshold),
        )
    return None


def malformed_fields(packet):
    """Return an alert if a discovery packet has fields you did not expect.

    Three cases: a payload on UDP/631 that is not a parseable browse record,
    an advertised host that differs from the datagram's sender, or
    unreasonably long location/info fields.
    """
    payload = browse_payload(packet)
    if payload is None:
        return None
    record = parse_browse(payload)
    if record is None:
        return alert(
            "malformed-discovery",
            packet,
            "unparseable browse record (%d bytes)" % len(payload),
        )
    if record["host"] and record["host"] != packet[IP].src:
        return alert(
            "address-mismatch",
            packet,
            "advertised host %s differs from sender %s"
            % (record["host"], packet[IP].src),
        )
    oversized = [f for f in (record["location"], record["info"]) if len(f) > 512]
    if oversized:
        return alert(
            "malformed-discovery",
            packet,
            "oversized browse field(s), longest %d bytes" % max(map(len, oversized)),
        )
    return None


def inspect_packet(packet, args, state):
    if not packet.haslayer(IP):
        return []
    remember_advertisement(packet, state)
    findings = [
        unauthorized_advertisement(packet, args.allow),
        suspicious_ipp(packet, args.allow, state),
        repeated_discovery(packet, state, args.repeat_threshold),
        malformed_fields(packet),
    ]
    return [item for item in findings if item]


def load_packets(args):
    if args.pcap:
        LOG.info("reading %s", args.pcap)
        return list(rdpcap(args.pcap))
    LOG.info("sniffing on %s (Ctrl-C stops monitoring and exports alerts)", args.iface)
    packets = []
    try:
        sniff(
            iface=args.iface,
            count=args.count or 0,
            prn=packets.append,
            store=False,
        )
    except KeyboardInterrupt:
        pass
    return packets


def write_alerts(path, alerts, fmt):
    if fmt == "json":
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(alerts, fh, indent=2)
            fh.write("\n")
        return
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=("time", "rule", "src", "dst", "summary", "detail")
        )
        writer.writeheader()
        writer.writerows(alerts)


def main(argv=None):
    args = parse_args(argv)
    args.allow = [entry.strip() for entry in args.allow if entry.strip()]
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    state = {"seen": {}}
    alerts = []
    for packet in load_packets(args):
        for item in inspect_packet(packet, args, state):
            LOG.warning("%s %s -> %s %s", item["rule"], item["src"], item["dst"], item["detail"])
            alerts.append(item)
    write_alerts(args.output, alerts, args.format)
    LOG.info("%d alert(s) written to %s", len(alerts), args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
