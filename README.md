🕵️‍♂️ Web-Based Packet Sniffer

A simple web-based packet sniffer written in Python using Scapy and Streamlit.
It captures packets asynchronously in a background thread and displays them in real time in a web UI.

⚠️ Disclaimer

This project is intended only for learning, testing, and ethical research on networks you own or have explicit permission to analyze.
Do NOT use this tool for unauthorized network monitoring.

✨ Features

Captures raw network packets using AsyncSniffer (Scapy)

Parses common protocols:
Ethernet, ARP
IP, TCP, UDP, ICMP
Displays packets in real time in a Streamlit web app

Shows:
Packet list with time, source, destination, protocol, length, info
Packets-per-second (PPS) metric (based on last 5 seconds)
Dropped packet counter
Supports BPF filters (e.g. tcp, udp port 53, host 8.8.8.8)

Lightweight and easy to extend

📦 Installation
1. Clone the repository
git clone https://github.com/thebetter-alex/web-based-packet-sniffer.git
cd web-based-packet-sniffer

2. Install dependencies

It’s recommended (but not required) to use a virtual environment.
pip install streamlit scapy streamlit-autorefresh

3. Windows-specific (Npcap)

On Windows, you must install Npcap to allow low-level packet capture:
Download and install from: https://npcap.com/
Make sure you check the option that allows WinPcap-compatible mode if needed.

▶️ Usage

From the project directory, run:
streamlit run main.py

This will:
Start the Streamlit server
Open (or let you open) a browser tab at something like:
http://localhost:8501
In the Web UI
Use the BPF Filter field in the sidebar to filter traffic (optional)
Examples:
tcp
udp port 53
host 8.8.8.8

Click ▶ Start to begin sniffing

Click ⏸ Stop to stop sniffing

Make sure you select the correct interface in the web ui, if you dont know which one, try them one by one.

📁 Project Structure

├── main.py

└── README.md

🔧 Requirements

Python 3.x

Libraries:
streamlit
scapy
streamlit-autorefresh

OS & Permissions:
Windows: Npcap installed, run with appropriate privileges
Linux/macOS: typically requires root/admin privileges to open raw sockets
e.g. sudo streamlit run main.py

🧱 How It Works (High-Level)

PacketSnifferThread
Runs AsyncSniffer in a background thread
Pushes captured packets into a queue.Queue with timestamps

Handler
Reads from the queue
Summarizes each packet into a dict: Time, Source, Destination, Protocol, Length, Info, etc.
Keeps a rolling buffer (up to max_packets)

StreamlitUI
Manages Streamlit session state
Sidebar controls: BPF filter, Start/Stop buttons, save button, selectable auto refrech rate.

Main window:
PPS (5s) metric
Dropped packets metric
A pandas.DataFrame showing the latest packets (newest on top)
Uses st_autorefresh to refresh the table when sniffing is running

🤝 Contributing

Pull requests are welcome!
Feel free to open issues for:

Bug reports

Feature requests (e.g. interface selection, PCAP export, protocol details)

UI enhancements
