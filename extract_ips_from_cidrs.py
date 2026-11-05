#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: pablo rotem
"""Expand IPv4 CIDRs/IPs from cidrs.txt into a streaming, resumable TXT file.

IPv6 ranges are deliberately not expanded; a single /32 would generate
2**96 addresses. See ipv6_cidrs.txt for the original IPv6 prefixes.
No third-party dependencies (Python 3.9+).
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import sys
from pathlib import Path


def read_networks(path: Path) -> tuple[list[ipaddress.IPv4Network], int, int]:
    if not path.is_file():
        raise FileNotFoundError(f"קובץ הקלט לא נמצא: {path}")
    networks: list[ipaddress.IPv4Network] = []
    ipv6_count = 0
    ignored = 0
    with path.open("r", encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, 1):
            raw = line.partition("#")[0].strip().rstrip(",").strip('"\'')
            if not raw:
                continue
            try:
                network = ipaddress.ip_network(raw, strict=False)
            except ValueError as exc:
                ignored += 1
                raise ValueError(f"שורה {line_number}: כתובת/טווח לא תקינים: {raw!r}") from exc
            if isinstance(network, ipaddress.IPv6Network):
                ipv6_count += 1
            else:
                networks.append(network)
    # collapse_addresses removes exact duplicates AND overlapping ranges.
    # This also prevents generating identical individual IPv4 addresses twice.
    merged = list(ipaddress.collapse_addresses(networks))
    return merged, ipv6_count, ignored


def plan_fingerprint(networks: list[ipaddress.IPv4Network]) -> str:
    digest = hashlib.sha256()
    for network in networks:
        digest.update(f"{network}\n".encode("ascii"))
    return digest.hexdigest()


def write_state(path: Path, state: dict) -> None:
    temp = path.with_name(path.name + ".tmp")
    with temp.open("w", encoding="utf-8") as stream:
        json.dump(state, stream, ensure_ascii=False, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def main() -> int:
    parser = argparse.ArgumentParser(description="פבלו רותם — חילוץ IPv4 מקובץ CIDR ללא אגירת כתובות בזיכרון")
    parser.add_argument("--input", default="cidrs.txt", help="קובץ טווחי CIDR וכתובות בודדות")
    parser.add_argument("--output", default="all_ips.txt", help="קובץ הפלט עם כתובת IPv4 אחת בכל שורה")
    parser.add_argument("--checkpoint-every", type=int, default=10000, help="שמירת מצב אחרי N כתובות")
    parser.add_argument("--max-new", type=int, default=0, help="הגבלת כמות הכתובות החדשות בריצה זו (0 = ללא הגבלה)")
    parser.add_argument("--reset", action="store_true", help="מוחק פלט ונקודת שמירה קודמים ומתחיל מחדש")
    args = parser.parse_args()
    if args.checkpoint_every < 1 or args.max_new < 0:
        parser.error("checkpoint-every חייב להיות חיובי ו-max-new חייב להיות 0 ומעלה")

    source = Path(args.input).expanduser().resolve()
    output = Path(args.output).expanduser().resolve()
    state_path = Path(str(output) + ".state.json")
    if source == output or source == state_path:
        parser.error("קובץ הקלט לא יכול להיות קובץ הפלט או קובץ נקודת השמירה")

    networks, ipv6_count, _ = read_networks(source)
    if not networks:
        raise RuntimeError("לא נמצאו טווחי IPv4 תקינים בקובץ")
    fingerprint = plan_fingerprint(networks)
    total_unique = sum(network.num_addresses for network in networks)
    print(f"[INFO] טווחי IPv4 ייחודיים לאחר איחוד חפיפות: {len(networks):,}", flush=True)
    print(f"[INFO] כמות כתובות IPv4 ייחודיות צפויה: {total_unique:,}", flush=True)
    print(f"[INFO] טווחי IPv6 שלא יורחבו: {ipv6_count:,}", flush=True)

    output.parent.mkdir(parents=True, exist_ok=True)
    if args.reset:
        output.unlink(missing_ok=True)
        state_path.unlink(missing_ok=True)

    if state_path.exists():
        if not output.exists():
            raise RuntimeError("נמצאה נקודת שמירה ללא קובץ פלט. שחזר גיבוי או הרץ עם --reset")
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if state.get("version") != 1 or state.get("fingerprint") != fingerprint:
            raise RuntimeError("רשימת הטווחים השתנתה מאז הריצה הקודמת. בחר קובץ פלט חדש או --reset")
        expected_size = int(state["output_bytes"])
        if output.stat().st_size < expected_size:
            raise RuntimeError("קובץ הפלט קצר מנקודת השמירה. יש לשחזר גיבוי")
        with output.open("r+b") as stream:
            stream.truncate(expected_size)
        print(f"[RESUME] ממשיכים אחרי {state['written']:,} כתובות", flush=True)
    else:
        if output.exists():
            raise RuntimeError("קובץ פלט קיים ללא state.json. השתמש ב--output אחר או ב--reset")
        output.touch()
        state = {
            "version": 1, "fingerprint": fingerprint,
            "network_index": 0, "next_offset": 0,
            "written": 0, "output_bytes": 0,
        }
        write_state(state_path, state)

    written = int(state["written"])
    this_run = 0
    index = int(state["network_index"])
    offset = int(state["next_offset"])

    def checkpoint(stream, next_index: int, next_offset: int) -> None:
        stream.flush()
        os.fsync(stream.fileno())
        state.update({
            "network_index": next_index,
            "next_offset": next_offset,
            "written": written,
            "output_bytes": stream.tell(),
        })
        write_state(state_path, state)
        print(f"[SAVE] {written:,}/{total_unique:,} כתובות ({100 * written / total_unique:.2f}%)", flush=True)

    # Writes every IP directly to disk, without constructing a list of IPs.
    # A checkpoint limits repeat work after an unexpected interruption.
    try:
        with output.open("ab") as stream:
            for network_index in range(index, len(networks)):
                network = networks[network_index]
                start = offset if network_index == index else 0
                base = int(network.network_address)
                for pos in range(start, network.num_addresses):
                    address = str(ipaddress.IPv4Address(base + pos))
                    stream.write((address + "\n").encode("ascii"))
                    written += 1
                    this_run += 1
                    if written % args.checkpoint_every == 0:
                        checkpoint(stream, network_index, pos + 1)
                    if args.max_new and this_run >= args.max_new:
                        checkpoint(stream, network_index, pos + 1)
                        print("[PAUSE] הגבלת --max-new הושגה; הרץ שוב להמשך", flush=True)
                        return 0
                offset = 0
                checkpoint(stream, network_index + 1, 0)
    except KeyboardInterrupt:
        print("\n[STOP] הריצה הופסקה; בהרצה הבאה נמשיך מנקודת השמירה האחרונה", file=sys.stderr)
        return 130

    print(f"[DONE] נוצר {output} עם {written:,} כתובות IPv4 ייחודיות", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)
