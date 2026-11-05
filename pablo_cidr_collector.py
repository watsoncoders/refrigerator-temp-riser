#!/usr/bin/env python3
# Author: pablo rotem
"""Passive Iran CIDR source collector with strictly allowlisted TXT export.

Uses only Python standard library. Downloads public registration-derived
IPv4/IPv6 datasets but never probes network hosts or services.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable

SOURCE_URLS = {
    "ipdeny_ipv4": "https://www.ipdeny.com/ipblocks/data/aggregated/ir-aggregated.zone",
    "ripe_country": (
        "https://stat.ripe.net/data/country-resource-list/data.json"
        "?resource=IR&v4_format=prefix"
    ),
    "ipverse_ipv4": (
        "https://raw.githubusercontent.com/ipverse/geo-ip-blocks/master/"
        "country/ir/ir-ipv4.txt"
    ),
    "ipverse_ipv6": (
        "https://raw.githubusercontent.com/ipverse/geo-ip-blocks/master/"
        "country/ir/ir-ipv6.txt"
    ),
    "xylem_ipv4": (
        "https://raw.githubusercontent.com/ravenscourt/xylem-ip-db/"
        "main/lists/ir.ipv4.txt"
    ),
    "xylem_ipv6": (
        "https://raw.githubusercontent.com/ravenscourt/xylem-ip-db/"
        "main/lists/ir.ipv6.txt"
    ),
}

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
MAX_DOWNLOAD_BYTES = 8 * 1024 * 1024
MAX_AUTHORIZED_IPV4 = 65536
MIN_IPV6_PREFIX = 64


def get_payload(url: str, timeout: int) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "PabloCIDRAudit/1.0 (passive network inventory)"},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(MAX_DOWNLOAD_BYTES + 1)
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise ValueError("download exceeds 8 MiB safety limit")
    return data


def parse_network(value: str) -> list[Network]:
    """Parse one network or inclusive IPv4/IPv6 range without host expansion."""
    value = value.strip().strip('"').strip("'")
    if not value:
        return []
    if "-" in value and "/" not in value:
        start_text, end_text = [item.strip() for item in value.split("-", 1)]
        start = ipaddress.ip_address(start_text)
        end = ipaddress.ip_address(end_text)
        if start.version != end.version or int(start) > int(end):
            raise ValueError("invalid IP start/end range")
        return list(ipaddress.summarize_address_range(start, end))
    return [ipaddress.ip_network(value, strict=True)]


def parse_plaintext(data: bytes, version: int | None = None) -> set[Network]:
    networks: set[Network] = set()
    for line_number, line in enumerate(data.decode("utf-8-sig").splitlines(), 1):
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            parsed = parse_network(value)
        except ValueError as exc:
            raise ValueError(f"invalid entry at source line {line_number}: {exc}") from exc
        for network in parsed:
            if version is None or network.version == version:
                networks.add(network)
    if not networks:
        raise ValueError("source returned no valid CIDR ranges")
    return networks


def parse_ripe(data: bytes) -> set[Network]:
    response = json.loads(data.decode("utf-8"))
    resources = response.get("data", {}).get("resources", {})
    networks: set[Network] = set()
    for family in ("ipv4", "ipv6"):
        for value in resources.get(family, []):
            for network in parse_network(value):
                networks.add(network)
    if not networks:
        raise ValueError("RIPEstat returned no prefixes")
    return networks


def read_authorized_scopes(path: Path) -> list[Network]:
    if not path.is_file():
        raise ValueError(f"authorization scope file not found: {path}")
    result: set[Network] = set()
    for number, raw_line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            scope = ipaddress.ip_network(line, strict=True)
        except ValueError as exc:
            raise ValueError(f"line {number}, invalid authorized CIDR: {exc}") from exc
        if isinstance(scope, ipaddress.IPv4Network):
            if scope.num_addresses > MAX_AUTHORIZED_IPV4:
                raise ValueError(
                    f"line {number}: IPv4 scope too broad (maximum /16 per scope)"
                )
        elif scope.prefixlen < MIN_IPV6_PREFIX:
            raise ValueError(f"line {number}: IPv6 scope too broad (minimum /64)")
        result.add(scope)
    if not result:
        raise ValueError("authorized scope file is empty")
    return list(ipaddress.collapse_addresses(sorted(result, key=sort_key))) if all(x.version == 4 for x in result) or all(x.version == 6 for x in result) else sorted(result, key=sort_key)


def sort_key(network: Network) -> tuple[int, int, int]:
    return (network.version, int(network.network_address), network.prefixlen)


def intersect_networks(public_networks: Iterable[Network], scopes: list[Network]) -> list[Network]:
    """Calculate only public-source/explicit-allowlist intersections."""
    clipped: list[Network] = []
    for cidr in public_networks:
        for scope in scopes:
            if cidr.version != scope.version or not cidr.overlaps(scope):
                continue
            low = max(int(cidr.network_address), int(scope.network_address))
            high = min(int(cidr.broadcast_address), int(scope.broadcast_address))
            address_type = ipaddress.IPv4Address if cidr.version == 4 else ipaddress.IPv6Address
            clipped.extend(ipaddress.summarize_address_range(address_type(low), address_type(high)))
    # IPv4 and IPv6 networks cannot be passed to collapse_addresses together.
    output: list[Network] = []
    for family in (4, 6):
        output.extend(ipaddress.collapse_addresses([x for x in clipped if x.version == family]))
    return sorted(output, key=sort_key)


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="איסוף פסיבי ממקורות IP ציבוריים, עם ייצוא טווחים מורשים בלבד"
    )
    parser.add_argument("--authorized-scopes", type=Path, required=True,
                        help="קובץ CIDR של רשתות שהורשית לבדוק; שורה לכל טווח")
    parser.add_argument("--output", type=Path, default=Path("authorized_ir_cidrs.txt"))
    parser.add_argument("--report", type=Path, default=Path("cidr_sources_report.json"))
    parser.add_argument("--timeout", type=int, default=25)
    parser.add_argument("--ipv4-only", action="store_true")
    args = parser.parse_args()
    if not 2 <= args.timeout <= 120:
        parser.error("--timeout must be 2..120 seconds")
    if args.output.resolve() == args.report.resolve():
        parser.error("output and report must be different paths")
    try:
        scopes = read_authorized_scopes(args.authorized_scopes)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    status: dict[str, dict[str, object]] = {}
    full_union: set[Network] = set()
    successful = 0
    for name, url in SOURCE_URLS.items():
        if args.ipv4_only and name.endswith("ipv6"):
            continue
        print(f"[+] מקור: {name}", flush=True)
        try:
            data = get_payload(url, args.timeout)
            if name == "ripe_country":
                values = parse_ripe(data)
            else:
                version = 6 if name.endswith("ipv6") else 4
                values = parse_plaintext(data, version)
            if args.ipv4_only:
                values = {network for network in values if network.version == 4}
            if not values:
                raise ValueError("no matching IP family")
            full_union.update(values)
            successful += 1
            status[name] = {"success": True, "cidr_records": len(values)}
        except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
            status[name] = {"success": False, "error": str(exc)}
            print(f"[!] שגיאה ב-{name}: {exc}", file=sys.stderr, flush=True)

    report = {
        "author": "pablo rotem",
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "purpose": "Passive IP registry comparison; authorized-range export only",
        "country_code": "IR",
        "sources": status,
        "successful_sources": successful,
        "source_cidr_record_count": len(full_union),
        "authorized_scope_count": len(scopes),
        "warning": (
            "Country association in registration databases does not verify live location, "
            "reachable devices, or ownership. No host scanning was performed."
        ),
    }
    if not successful:
        report["error"] = "All public sources failed. Existing output file was not modified."
        atomic_write(args.report, json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print("[!] כל המקורות נכשלו; לא נוצר קובץ יעד חדש.", file=sys.stderr)
        return 2

    filtered = intersect_networks(full_union, scopes)
    report["exported_authorized_cidr_count"] = len(filtered)
    report["output"] = str(args.output)
    atomic_write(args.output, "\n".join(str(network) for network in filtered) + ("\n" if filtered else ""))
    atomic_write(args.report, json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(f"[OK] מקורות שהצליחו: {successful}; טווחים מורשים לייצוא: {len(filtered)}")
    print(f"[OK] TXT: {args.output}; דוח JSON: {args.report}")
    if not filtered:
        print("[!] אין התאמה בין רשימות המקורות לבין טווחי ההרשאה שסיפקת.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
