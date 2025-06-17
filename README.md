# personal-firewall
A simple yet powerful personal firewall in Python with a GUI, real-time packet filtering, and customizable rules.
🔥 Personal Firewall – Python Based
A lightweight, rule-based personal firewall developed in Python, using Scapy for packet sniffing, Tkinter for GUI, and optional iptables integration on Linux.

📌 Features
✅ Live Packet Sniffing using Scapy

✅ Block traffic by IP, Port, or Protocol (TCP/UDP/ICMP)

✅ Rule Manager: Add & Remove rules dynamically

✅ Packet Logging with timestamp and reason

✅ View Logs & Stats: See which IPs were blocked and how often

✅ Simple GUI Interface (Tkinter)

✅ Timeout Handling to avoid hangs

🚧 Optional iptables integration for system-level blocking (coming soon)

🛠️ Tools & Technologies
Python 3.8+

Scapy

Tkinter (for GUI)

iptables (for deeper Linux integration)

OS: Tested on Kali Linux / Ubuntu

How to Run

# 1. Clone the repo
git clone https://github.com/yourusername/personal-firewall-python.git
cd personal-firewall-python

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run with sudo (for raw socket access)
sudo python3 firewall.py
❗Note: GUI requires a display environment. Use xhost or run inside a desktop environment.
