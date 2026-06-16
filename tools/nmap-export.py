#!/usr/bin/env python3
"""nmap-export -- convert Nmap native JSON (-oJ) into security standards.

Part of the nmapv2 enhanced fork (proposal P06). Reads the stable JSON produced by
`nmap -oJ` and emits SARIF 2.1.0, OCSF, or STIX 2.1. Dependency-free (stdlib only).

Usage:
    nmap -sV -oJ - <target> | tools/nmap-export.py --format sarif
    tools/nmap-export.py --format stix scan.json -o scan.stix.json

Each open port becomes one finding/object; host context (address, hostnames) is
attached. The reliability score (P14) and per-host diagnostics (P15) are carried
through where the target schema has somewhere to put them.
"""
import argparse
import json
import sys
import uuid
from datetime import datetime, timezone

TOOL_NAME = "nmap"
TOOL_URI = "https://nmap.org"
# Stable namespace so STIX/identifiers are reproducible across runs of the same scan.
NS = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _det_id(prefix, *parts):
    """Deterministic STIX id: <type>--<uuid5(namespace, parts)>."""
    return "%s--%s" % (prefix, uuid.uuid5(NS, "|".join(str(p) for p in parts)))


def load(run_json):
    """Return (meta, hosts) from a parsed nmaprun document."""
    run = run_json["nmaprun"]
    return run, run.get("hosts", [])


def iter_open_ports(hosts):
    """Yield (host, addr, addrtype, port) for every open port."""
    for h in hosts:
        addrs = h.get("addresses", [])
        addr = addrs[0]["addr"] if addrs else "unknown"
        addrtype = addrs[0].get("addrtype", "ipv4") if addrs else "ipv4"
        for p in h.get("ports", []):
            if p.get("state") == "open":
                yield h, addr, addrtype, p


def _svc_str(port):
    svc = port.get("service", {}) or {}
    bits = [svc.get("name", "")]
    if svc.get("product"):
        bits.append(svc["product"])
    if svc.get("version"):
        bits.append(svc["version"])
    return " ".join(b for b in bits if b).strip()


# --------------------------------------------------------------------------- SARIF
def to_sarif(run, hosts):
    results = []
    for _h, addr, _at, p in iter_open_ports(hosts):
        proto, portid = p.get("protocol", "tcp"), p.get("portid")
        svc = _svc_str(p) or "unknown"
        results.append({
            "ruleId": "nmap/open-port",
            "level": "note",
            "message": {"text": "Open %s port %s on %s (%s)" % (proto, portid, addr, svc)},
            "locations": [{
                "logicalLocations": [{
                    "name": "%s:%s/%s" % (addr, portid, proto),
                    "kind": "networkEndpoint",
                }]
            }],
            "properties": {
                "host": addr, "port": portid, "protocol": proto,
                "service": (p.get("service", {}) or {}).get("name"),
                "reliability": p.get("reliability"),
                "reliability_level": p.get("reliability_level"),
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "informationUri": TOOL_URI,
                "version": run.get("version", "unknown"),
                "rules": [{
                    "id": "nmap/open-port",
                    "name": "OpenPort",
                    "shortDescription": {"text": "An open network port was detected."},
                    "defaultConfiguration": {"level": "note"},
                }],
            }},
            "invocations": [{
                "commandLine": run.get("args", ""),
                "executionSuccessful": True,
            }],
            "results": results,
        }],
    }


# ---------------------------------------------------------------------------- OCSF
def to_ocsf(run, hosts):
    """OCSF Network Activity findings (category_uid 4, class_uid 4001)."""
    out = []
    ts = run.get("start")
    for _h, addr, at, p in iter_open_ports(hosts):
        portid = p.get("portid")
        svc = p.get("service", {}) or {}
        out.append({
            "category_uid": 4,
            "category_name": "Network Activity",
            "class_uid": 4001,
            "class_name": "Network Activity",
            "activity_id": 1,
            "type_uid": 400101,
            "severity_id": 1,
            "time": (ts * 1000) if isinstance(ts, int) else None,
            "metadata": {
                "product": {"name": TOOL_NAME, "vendor_name": "Nmap",
                            "version": run.get("version", "unknown")},
                "version": "1.1.0",
            },
            "dst_endpoint": {
                "ip": addr,
                "port": portid,
                "type": "ipv6" if at == "ipv6" else "ipv4",
                "svc_name": svc.get("name"),
            },
            "connection_info": {"protocol_name": p.get("protocol", "tcp")},
            "observables": [
                {"name": "dst_endpoint.ip", "type": "IP Address", "value": addr},
                {"name": "dst_endpoint.port", "type": "Port", "value": str(portid)},
            ],
            "status": "open",
            "unmapped": {
                "reliability": p.get("reliability"),
                "service": _svc_str(p) or None,
            },
        })
    return out


# ---------------------------------------------------------------------------- STIX
def to_stix(run, hosts):
    objects = []
    created = _now_iso()
    for h in hosts:
        addrs = h.get("addresses", [])
        if not addrs:
            continue
        addr = addrs[0]["addr"]
        at = addrs[0].get("addrtype", "ipv4")
        addr_type = "ipv6-addr" if at == "ipv6" else ("mac-addr" if at == "mac" else "ipv4-addr")
        host_id = _det_id(addr_type, addr_type, addr)
        objects.append({"type": addr_type, "id": host_id, "value": addr})

        for p in h.get("ports", []):
            if p.get("state") != "open":
                continue
            portid = p.get("portid")
            proto = p.get("protocol", "tcp")
            nt_id = _det_id("network-traffic", addr, proto, portid)
            objects.append({
                "type": "network-traffic",
                "id": nt_id,
                "dst_ref": host_id,
                "protocols": ["ipv6" if at == "ipv6" else "ipv4", proto],
                "dst_port": portid,
            })
            svc = p.get("service", {}) or {}
            if svc.get("name") or svc.get("product"):
                name = svc.get("product") or svc.get("name")
                sw = {"type": "software", "id": _det_id("software", addr, portid, name),
                      "name": name}
                if svc.get("version"):
                    sw["version"] = svc["version"]
                if svc.get("cpe"):
                    sw["cpe"] = svc["cpe"][0]
                objects.append(sw)

    return {
        "type": "bundle",
        "id": _det_id("bundle", run.get("args", ""), run.get("start", "")),
        "spec_version": "2.1",
        "objects": objects or [{
            # A bundle must not be empty; emit a marker identity if nothing was found.
            "type": "identity", "id": _det_id("identity", "nmap"),
            "name": "nmap", "created": created,
        }],
    }


FORMATS = {"sarif": to_sarif, "ocsf": to_ocsf, "stix": to_stix}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Convert Nmap -oJ JSON to SARIF/OCSF/STIX.")
    ap.add_argument("input", nargs="?", default="-",
                    help="Nmap JSON file (default: stdin)")
    ap.add_argument("--format", "-f", required=True, choices=sorted(FORMATS),
                    help="output format")
    ap.add_argument("-o", "--output", default="-", help="output file (default: stdout)")
    args = ap.parse_args(argv)

    raw = sys.stdin.read() if args.input == "-" else open(args.input).read()
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as e:
        sys.stderr.write("error: input is not valid JSON: %s\n" % e)
        return 2
    if "nmaprun" not in doc:
        sys.stderr.write("error: input does not look like Nmap -oJ output "
                         "(missing 'nmaprun')\n")
        return 2

    run, hosts = load(doc)
    result = FORMATS[args.format](run, hosts)
    text = json.dumps(result, indent=2)

    if args.output == "-":
        sys.stdout.write(text + "\n")
    else:
        with open(args.output, "w") as f:
            f.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
