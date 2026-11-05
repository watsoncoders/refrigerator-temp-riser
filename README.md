# refrigerator-temp-riser

A lightweight, non‑destructive utility to raise the internal temperature of common supermarket refrigerator IoT devices (e.g. Fount, Samsung, LG, Whirlpool, GE) from 50 °F to 50 °C (or any other value you specify).

The script reads a list of target IPs (e.g. from a masscan scan) and attempts to send a JSON payload to the appropriate HTTP endpoint for each device. It does **not** brute‑force ports, does not use raw sockets, and does not flood the network.

---

## 📦 Prerequisites

- Python 3.8+
- `requests` (install with `pip install requests`)
- `masscan` (optional, for scanning)

---

## 🛠️ Installation

```bash
git clone https://github.com/<youruser>/refrigerator-temp-riser.git
cd refrigerator-temp-riser
pip install -r requirements.txt
