from fastapi import FastAPI, WebSocket
from fastapi.responses import FileResponse, JSONResponse
from contextlib import asynccontextmanager
from pathlib import Path
import subprocess
import asyncio
import httpx
import sqlite3
import time
import threading
import shutil
import os
import logging
import re

# ---------------------------
# LOGGING
# ---------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

# ---------------------------
# SCAPY (opcional — precisa de root)
# ---------------------------
try:
    from scapy.layers.inet import IP
    from scapy.sendrecv import AsyncSniffer
    import scapy.all as scapy
    SCAPY_OK = True
    logger.info("Scapy carregado com sucesso")
except Exception as e:
    logger.warning(f"Scapy indisponível ({e}). Usando fallback via ss/netstat.")
    SCAPY_OK = False

# ---------------------------
# CONFIG BASE
# ---------------------------
IPTABLES    = shutil.which("iptables") or "/usr/sbin/iptables"
IPS_SEGUROS = ["127.", "192.168.", "10.", "0.0.0.0", "224.", "255."]
BASE_DIR    = Path(__file__).resolve().parent

# ---------------------------
# DETECÇÃO AUTOMÁTICA DE INTERFACE
# ---------------------------
def detectar_interface() -> str:
    """
    Prioridade:
      1. Variável de ambiente NET_IFACE (override manual)
      2. Interface com rota default (ip route get 8.8.8.8)
      3. Primeira interface UP com IP que não seja loopback (/proc/net/if_inet6 / ip addr)
      4. scapy.conf.iface como último recurso
      5. "any" se tudo falhar
    """
    # 1. override manual
    env = os.getenv("NET_IFACE", "").strip()
    if env:
        logger.info(f"Interface: variável NET_IFACE → {env}")
        return env

    # 2. rota default — mais confiável
    try:
        r = subprocess.run(
            ["ip", "route", "get", "8.8.8.8"],
            capture_output=True, text=True, timeout=3
        )
        # saída: "8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.10 ..."
        m = re.search(r"\bdev\s+(\S+)", r.stdout)
        if m:
            iface = m.group(1)
            logger.info(f"Interface detectada via rota default: {iface}")
            return iface
    except Exception as e:
        logger.debug(f"ip route falhou: {e}")

    # 3. primeira interface UP com IPv4 (via `ip addr`)
    try:
        r = subprocess.run(
            ["ip", "-o", "-4", "addr", "show", "up"],
            capture_output=True, text=True, timeout=3
        )
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                iface = parts[1]
                if iface != "lo":
                    logger.info(f"Interface detectada via ip addr: {iface}")
                    return iface
    except Exception as e:
        logger.debug(f"ip addr falhou: {e}")

    # 4. scapy fallback
    if SCAPY_OK:
        iface = scapy.conf.iface
        logger.info(f"Interface via scapy.conf.iface: {iface}")
        return iface

    logger.warning("Não foi possível detectar interface — usando 'any'")
    return "any"

INTERFACE = detectar_interface()

# ---------------------------
# ESTADO GLOBAL
# ---------------------------
traffic: dict[str, dict] = {}
traffic_lock = threading.Lock()

ip_activity: dict[str, list] = {}
geo_cache: dict[str, dict]   = {}

clients: set = set()
clients_lock = asyncio.Lock()

# ---------------------------
# DATABASE
# ---------------------------
db_lock = threading.Lock()
_conn   = sqlite3.connect("database.db", check_same_thread=False, isolation_level=None)
_cur    = _conn.cursor()
_cur.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        ip        TEXT,
        action    TEXT,
        timestamp REAL
    )
""")

def db_log(ip: str, action: str):
    with db_lock:
        _cur.execute(
            "INSERT INTO logs (ip, action, timestamp) VALUES (?, ?, ?)",
            (ip, action, time.time())
        )

# ---------------------------
# FIREWALL
# ---------------------------
def ip_seguro(ip: str) -> bool:
    return any(ip.startswith(p) for p in IPS_SEGUROS)

def _iptables(*args):
    return subprocess.run([IPTABLES, *args], capture_output=True, text=True)

def bloquear_ip(ip: str) -> dict:
    if ip_seguro(ip):
        return {"status": "skipped", "reason": "IP local/seguro"}
    try:
        r = _iptables("-A", "INPUT", "-s", ip, "-j", "DROP")
        if r.returncode == 0:
            db_log(ip, "BLOCK")
            logger.info(f"[BLOCK] {ip}")
            return {"status": "blocked", "ip": ip}
        return {"status": "error", "detail": r.stderr.strip()}
    except Exception as e:
        return {"status": "error", "detail": str(e)}

def liberar_ip(ip: str) -> dict:
    try:
        r = _iptables("-D", "INPUT", "-s", ip, "-j", "DROP")
        if r.returncode == 0:
            db_log(ip, "UNBLOCK")
            logger.info(f"[UNBLOCK] {ip}")
            return {"status": "unblocked", "ip": ip}
        return {"status": "error", "detail": r.stderr.strip()}
    except Exception as e:
        return {"status": "error", "detail": str(e)}

# ---------------------------
# DETECÇÃO DE ATAQUE
# ---------------------------
def detectar_ataque(ip: str):
    now = time.time()
    ip_activity.setdefault(ip, [])
    ip_activity[ip].append(now)
    recentes = [t for t in ip_activity[ip] if now - t < 10]
    if len(recentes) > 30 and not ip_seguro(ip):
        logger.warning(f"[ATAQUE DETECTADO] {ip}")
        bloquear_ip(ip)

# ---------------------------
# SNIFFER (Scapy, root)
# ---------------------------
def _processar_pacote(pkt):
    if not pkt.haslayer(IP):
        return
    ip_src  = pkt[IP].src
    tamanho = len(pkt)
    now     = time.time()
    with traffic_lock:
        e = traffic.setdefault(ip_src, {"packets": 0, "bytes": 0, "last_seen": now, "source": "scapy"})
        e["packets"]   += 1
        e["bytes"]     += tamanho
        e["last_seen"]  = now
    detectar_ataque(ip_src)

def iniciar_sniffer():
    if not SCAPY_OK:
        return
    try:
        sniffer = AsyncSniffer(
            iface=INTERFACE,
            prn=_processar_pacote,
            store=False,
            filter="ip"
        )
        sniffer.start()
        logger.info(f"Sniffer Scapy iniciado em {INTERFACE}")
    except Exception as e:
        logger.error(f"Sniffer falhou: {e}")

# ---------------------------
# FALLBACK: conexões via `ss`
# (funciona sem root, atualiza traffic se Scapy não capturou)
# ---------------------------
_IP_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})$")

def _ips_via_ss() -> list[str]:
    """Retorna IPs externos ativos via `ss -tunap`."""
    try:
        r = subprocess.run(["ss", "-tunap"], capture_output=True, text=True, timeout=3)
        ips = set()
        for line in r.stdout.splitlines():
            parts = line.split()
            # colunas peer address: índice 5 em ss
            for part in parts[4:6]:
                host = part.rsplit(":", 1)[0].strip("[]")
                if _IP_RE.match(host) and not ip_seguro(host):
                    ips.add(host)
        return list(ips)
    except Exception as e:
        logger.debug(f"ss falhou: {e}")
        return []

def _ips_via_netstat() -> list[str]:
    """Fallback extra via netstat."""
    try:
        r = subprocess.run(["netstat", "-tunp"], capture_output=True, text=True, timeout=3)
        ips = set()
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                for col in parts[3:5]:
                    host = col.rsplit(":", 1)[0]
                    if _IP_RE.match(host) and not ip_seguro(host):
                        ips.add(host)
        return list(ips)
    except Exception:
        return []

def atualizar_via_ss():
    """Popula `traffic` com IPs de ss/netstat (usado quando Scapy não roda)."""
    ips = _ips_via_ss() or _ips_via_netstat()
    now = time.time()
    with traffic_lock:
        for ip in ips:
            if ip not in traffic:
                traffic[ip] = {"packets": 0, "bytes": 0, "last_seen": now, "source": "ss"}
            traffic[ip]["last_seen"] = now
            traffic[ip]["packets"]  += 1   # incremento simbólico

        # remove IPs que sumiram há mais de 30s
        stale = [ip for ip, v in traffic.items() if now - v["last_seen"] > 30]
        for ip in stale:
            del traffic[ip]

# ---------------------------
# GEO IP
# ---------------------------
async def geo_ip(ip: str) -> dict:
    if ip in geo_cache:
        return geo_cache[ip]
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(f"http://ip-api.com/json/{ip}")
            d = r.json()
            if d.get("status") == "success":
                result = {
                    "country": d.get("country", ""),
                    "city":    d.get("city", ""),
                    "lat":     d.get("lat"),
                    "lon":     d.get("lon"),
                    "isp":     d.get("isp", ""),
                }
                geo_cache[ip] = result
                return result
    except Exception as e:
        logger.debug(f"geo_ip({ip}) falhou: {e}")
    return {}

# ---------------------------
# WEBSOCKET
# ---------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # inicia sniffer Scapy em thread separada
    threading.Thread(target=iniciar_sniffer, daemon=True).start()
    task = asyncio.create_task(monitor())
    logger.info("Monitor iniciado")
    yield
    task.cancel()

app = FastAPI(lifespan=lifespan)

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    logger.info(f"WebSocket conectado: {ws.client}")
    async with clients_lock:
        clients.add(ws)
    try:
        while True:
            await ws.receive_text()   # mantém conexão viva
    except Exception:
        pass
    finally:
        async with clients_lock:
            clients.discard(ws)
        logger.info(f"WebSocket desconectado: {ws.client}")

# ---------------------------
# BROADCAST
# ---------------------------
async def broadcast():
    # se Scapy não roda, usa ss como fonte de dados
    if not SCAPY_OK:
        atualizar_via_ss()

    with traffic_lock:
        snapshot = {ip: dict(v) for ip, v in traffic.items()}

    # busca geo só dos IPs sem cache ainda
    ips  = list(snapshot.keys())
    geos = await asyncio.gather(*[geo_ip(ip) for ip in ips])

    payload = [
        {
            "ip":        ip,
            "packets":   snapshot[ip]["packets"],
            "bytes":     snapshot[ip]["bytes"],
            "last_seen": snapshot[ip]["last_seen"],
            "source":    snapshot[ip].get("source", "?"),
            "geo":       geos[i],
        }
        for i, ip in enumerate(ips)
    ]

    # envia sempre (mesmo lista vazia) para o front saber que está vivo
    async with clients_lock:
        dead = []
        for c in clients:
            try:
                await c.send_json(payload)
            except Exception:
                dead.append(c)
        for d in dead:
            clients.discard(d)

    if ips:
        logger.debug(f"Broadcast: {len(ips)} IPs → {len(clients)} clientes")

# ---------------------------
# MONITOR LOOP
# ---------------------------
async def monitor():
    while True:
        try:
            await broadcast()
        except Exception as e:
            logger.exception(f"Erro no monitor: {e}")
        await asyncio.sleep(2)

# ---------------------------
# ROTAS HTTP
# ---------------------------
@app.get("/")
def home():
    return FileResponse(BASE_DIR / "network-monitor.html")

@app.get("/logs")
def get_logs():
    with db_lock:
        rows = _cur.execute(
            "SELECT ip, action, timestamp FROM logs ORDER BY timestamp DESC LIMIT 100"
        ).fetchall()
    return [{"ip": r[0], "action": r[1], "timestamp": r[2]} for r in rows]

@app.get("/traffic")
def get_traffic():
    """Endpoint de diagnóstico — mostra traffic dict atual."""
    with traffic_lock:
        return dict(traffic)

@app.get("/debug")
def debug():
    """Diagnóstico: mostra IPs via ss/netstat e estado do Scapy."""
    ss_ips = _ips_via_ss()
    ns_ips = _ips_via_netstat()
    with traffic_lock:
        tr = dict(traffic)
    return {
        "scapy_ok":     SCAPY_OK,
        "interface":    INTERFACE,
        "ss_ips":       ss_ips,
        "netstat_ips":  ns_ips,
        "traffic_keys": list(tr.keys()),
        "clients":      len(clients),
    }

@app.post("/block/{ip}")
def block(ip: str):
    return JSONResponse(bloquear_ip(ip))

@app.post("/unblock/{ip}")
def unblock(ip: str):
    return JSONResponse(liberar_ip(ip))