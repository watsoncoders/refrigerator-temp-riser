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
git clone https://github.com/watsoncoders/refrigerator-temp-riser.git
cd refrigerator-temp-riser
pip install -r requirements.txt
🎯 Usage
1️⃣ Collect targets with masscan
# Scan your subnet for common refrigerator ports
masscan 192.168.1.0/24 -p80,443,8080 --rate=5000 -oJ masscan.json
Extract the discovered IPs (adjust the jq filter to match your output format):


jq -r '.hosts[].start' masscan.json | sort -u > targets.txt

python3 rtps.py targets.txt -t 50 -d 1

Arguments:

-t – target temperature in °C (default: 50.0)
-d – delay between devices in seconds (default: 1.0)
The script will print a short summary of success/failure for each device.

🧩 Extending for other models
Edit the MODELS dictionary in rtps.py. Each entry is:

"brand_name": ("/api/endpoint/path", "json_key"),

You can also add new health‑check paths in HEALTH_ENDPOINTS to improve model detection.

⚠️ Safety & Ethics
Only run on devices you own or have explicit permission to test.
The script does not attempt authentication unless you add your own token.
Avoid running on large networks without throttling to prevent unnecessary load.
📜 License
MIT

🤝 Contributing
Contributions are welcome! Please open an issue or pull request for new models, better error handling, or documentation improvements.

📚 Resources
masscan: https://github.com/robertdavidgraham/masscan
requests: https://requests.readthedocs.io/
