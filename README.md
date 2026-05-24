# 🔥 Paranoic — Real-Time Firewall Dashboard

> Network traffic monitor and firewall manager with live world map, WebSocket streaming, geo IP lookup and automatic attack detection.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat-square&logo=fastapi&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.5+-1F6FEB?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

---

## Features

- **Live packet capture** via Scapy (deep inspection) with automatic fallback to `ss`/`netstat` when running without root
- **Auto interface detection** — finds the active network interface via routing table (`ip route get 8.8.8.8`), no manual config needed
- **World map** with real-time lines drawn from your server to each connected IP (Leaflet.js)
- **Geo IP lookup** — country, city, ISP and coordinates via ip-api.com (cached per session)
- **Automatic attack detection** — blocks IPs with more than 30 packets in 10 seconds via `iptables`
- **One-click block/unblock** per IP directly from the dashboard
- **WebSocket streaming** with automatic reconnection and HTTP poll fallback
- **Firewall log** persisted in SQLite with timestamp and action history
- **Debug overlay** in the UI showing WebSocket state, message count, active interface and errors

---

## Screenshots

> Dashboard running with live connections, world map lines and firewall log panel.

---

## Requirements

- Python 3.10+
- Linux (uses `iptables` and `ss`)
- Root/sudo for Scapy packet capture and iptables rules

---

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/paranoic.git
cd netwatch

# Install dependencies
pip install fastapi uvicorn scapy httpx
```

---

## Usage

**With root** (full features — Scapy capture + iptables):
```bash
sudo $(which uvicorn) main:app --host 0.0.0.0 --port 8000 --reload
```

**Without root** (fallback mode — uses `ss`/`netstat`, no iptables):
```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

**Force a specific network interface:**
```bash
NET_IFACE=eth0 sudo $(which uvicorn) main:app --host 0.0.0.0 --port 8000
```

Open the dashboard at `http://localhost:8000`

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Dashboard UI |
| `GET` | `/traffic` | Current traffic dict (raw) |
| `GET` | `/logs` | Last 100 firewall actions |
| `GET` | `/debug` | Diagnostic info (interface, Scapy status, active IPs) |
| `POST` | `/block/{ip}` | Block an IP via iptables |
| `POST` | `/unblock/{ip}` | Remove iptables block rule |
| `WS` | `/ws` | WebSocket stream (2s interval) |

### WebSocket payload format

```json
[
  {
    "ip": "203.0.113.42",
    "packets": 134,
    "bytes": 87432,
    "last_seen": 1716998400.0,
    "source": "scapy",
    "geo": {
      "country": "Brazil",
      "city": "São Paulo",
      "lat": -23.5505,
      "lon": -46.6333,
      "isp": "Claro"
    }
  }
]
```

---

## Architecture

```
main.py
├── Scapy AsyncSniffer       # packet capture (root only)
├── ss/netstat fallback      # connection list (no root)
├── Interface auto-detection # ip route → ip addr → scapy → "any"
├── Geo IP cache             # ip-api.com lookup, cached per session
├── Attack detector          # >30 pkts/10s → auto block
├── WebSocket broadcaster    # every 2s → all connected clients
└── SQLite logger            # block/unblock history

network-monitor.html
├── Leaflet.js world map     # markers + lines per IP
├── WebSocket client         # auto-reconnect with exponential backoff
├── HTTP poll fallback       # /traffic every 3s if WS fails
└── Debug bar                # live WS state, msg count, interface
```

---

## Diagnostic

If the dashboard shows no data, open:

```
http://localhost:8000/debug
```

Expected response:
```json
{
  "scapy_ok": true,
  "interface": "eth0",
  "ss_ips": ["8.8.8.8", "142.250.1.1"],
  "traffic_keys": ["8.8.8.8"],
  "clients": 1
}
```

- `scapy_ok: false` → run with `sudo` for full capture
- `ss_ips` empty → no external connections active at the moment
- `traffic_keys` empty → data not reaching the traffic dict (check logs)

---

## License

MIT — free to use, modify and distribute.
