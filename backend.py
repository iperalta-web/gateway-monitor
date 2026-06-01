"""
ChirpStack Gateway Monitor — Backend
Connects to ChirpStack via gRPC-web and serves a REST API for the dashboard.
"""
import os
import smtplib
import struct
import threading
import time
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests as http_requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("gw-monitor")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CHIRPSTACK_URL = "https://chripstack.0giotsolutions.com"
TENANT_ID = "4bafa68e-9663-4fc9-931e-6356266d0efe"
POLL_INTERVAL = 30

# ─── Email config (from env vars) ─────────────────────────────────────────────
EMAIL_FROM    = os.environ.get("EMAIL_FROM", "")
EMAIL_TO      = os.environ.get("EMAIL_TO", "")
SMTP_HOST     = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER     = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")

def send_email_alert(alert: dict):
    if not all([EMAIL_FROM, EMAIL_TO, SMTP_USER, SMTP_PASSWORD]):
        log.warning("Email not configured — skipping alert email")
        return
    try:
        is_offline = alert["type"] == "OFFLINE"
        subject = f"{'🔴 Gateway DESCONECTADO' if is_offline else '🟢 Gateway RECONECTADO'}: {alert['name']}"
        ts = datetime.fromisoformat(alert["time"]).strftime("%d/%m/%Y %H:%M:%S UTC")

        html = f"""
        <html><body style="font-family:sans-serif;background:#0f1117;color:#e1e4e8;padding:24px">
          <div style="max-width:500px;margin:auto;background:#161b22;border:1px solid #30363d;
                      border-radius:10px;overflow:hidden">
            <div style="background:{'#1f0d0d' if is_offline else '#0d1f0d'};
                        border-bottom:1px solid {'#da3633' if is_offline else '#238636'};
                        padding:16px 24px">
              <h2 style="margin:0;color:{'#f85149' if is_offline else '#56d364'}">
                {'🔴 Gateway Desconectado' if is_offline else '🟢 Gateway Reconectado'}
              </h2>
            </div>
            <div style="padding:24px">
              <table style="width:100%;border-collapse:collapse">
                <tr><td style="color:#8b949e;padding:6px 0;width:130px">Gateway</td>
                    <td style="font-weight:600">{alert['name']}</td></tr>
                <tr><td style="color:#8b949e;padding:6px 0">ID</td>
                    <td style="font-family:monospace;font-size:0.9em">{alert['gateway_id']}</td></tr>
                <tr><td style="color:#8b949e;padding:6px 0">Estado</td>
                    <td style="color:{'#f85149' if is_offline else '#56d364'};font-weight:700">
                      {'OFFLINE' if is_offline else 'ONLINE'}</td></tr>
                <tr><td style="color:#8b949e;padding:6px 0">Hora</td>
                    <td>{ts}</td></tr>
              </table>
              <div style="margin-top:20px;padding:12px;background:#0d1117;border-radius:6px;
                          font-size:0.85em;color:#8b949e">
                {'Este gateway dejó de reportar. Verifica la conexión física y de red.'
                 if is_offline else
                 'El gateway ha vuelto a estar en línea y reportando correctamente.'}
              </div>
              <div style="margin-top:16px;text-align:center">
                <a href="https://chripstack.0giotsolutions.com"
                   style="background:#1f6feb;color:#fff;padding:10px 20px;border-radius:6px;
                          text-decoration:none;font-size:0.88em">
                  Ver en ChirpStack →
                </a>
              </div>
            </div>
            <div style="padding:12px 24px;border-top:1px solid #30363d;font-size:0.75em;color:#6e7681">
              IotNet — Gateway Monitor · Alerta automática
            </div>
          </div>
        </body></html>
        """

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = EMAIL_FROM
        msg["To"]      = EMAIL_TO
        msg.attach(MIMEText(alert["message"], "plain"))
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.sendmail(EMAIL_FROM, EMAIL_TO.split(","), msg.as_string())

        log.info(f"Email enviado a {EMAIL_TO}: {subject}")
    except Exception as e:
        log.error(f"Error enviando email: {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    api_key = os.environ.get("CHIRPSTACK_API_KEY", "")
    if api_key:
        state["token"] = api_key
        log.info("API key loaded from CHIRPSTACK_API_KEY env var")
    t = threading.Thread(target=poll, daemon=True)
    t.start()
    log.info("Polling thread started — interval %ds", POLL_INTERVAL)
    yield

app = FastAPI(title="Gateway Monitor", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ─── Proto / gRPC-web helpers ─────────────────────────────────────────────────

def _vi_enc(n: int) -> bytes:
    out = b""
    while n > 127:
        out += bytes([0x80 | (n & 0x7F)]); n >>= 7
    return out + bytes([n])

def _vi_dec(data: bytes, pos: int):
    r, s = 0, 0
    while pos < len(data):
        b = data[pos]; pos += 1
        r |= (b & 0x7F) << s
        if not (b & 0x80): break
        s += 7
    return r, pos

def _sf(f: int, v: str) -> bytes:
    enc = v.encode()
    return _vi_enc((f << 3) | 2) + _vi_enc(len(enc)) + enc

def _intf(f: int, v: int) -> bytes:
    return _vi_enc((f << 3) | 0) + _vi_enc(v)

def _grpc_frame(body: bytes) -> bytes:
    return bytes([0]) + struct.pack(">I", len(body)) + body

def decode_proto(data: bytes) -> dict:
    result: dict = {}
    pos = 0
    while pos < len(data):
        tag, pos = _vi_dec(data, pos)
        field = tag >> 3; wire = tag & 0x7
        if wire == 2:
            length, pos = _vi_dec(data, pos)
            val = data[pos:pos + length]; pos += length
            try: decoded = val.decode("utf-8")
            except Exception: decoded = val  # keep bytes
            if field in result:
                if not isinstance(result[field], list): result[field] = [result[field]]
                result[field].append(decoded)
            else: result[field] = decoded
        elif wire == 0:
            v, pos = _vi_dec(data, pos); result[field] = v
        elif wire == 1:
            result[field] = struct.unpack("<d", data[pos:pos+8])[0]; pos += 8
        elif wire == 5:
            result[field] = struct.unpack("<f", data[pos:pos+4])[0]; pos += 4
        else:
            break
    return result

def _grpc_post(path: str, proto_body: bytes, token: str) -> bytes:
    r = http_requests.post(
        f"{CHIRPSTACK_URL}{path}",
        data=_grpc_frame(proto_body),
        headers={
            "Content-Type": "application/grpc-web+proto",
            "X-Grpc-Web": "1",
            "Accept": "application/grpc-web+proto",
            "Authorization": f"Bearer {token}",
        },
        timeout=10,
    )
    grpc_status = r.headers.get("Grpc-Status", "0")
    grpc_msg = r.headers.get("Grpc-Message", "")
    if grpc_status not in ("", "0"):
        raise RuntimeError(f"gRPC {grpc_status}: {grpc_msg}")
    if len(r.content) < 5:
        return b""
    length = struct.unpack(">I", r.content[1:5])[0]
    return r.content[5:5 + length]

# ─── State ────────────────────────────────────────────────────────────────────

state = {
    "token": None,
    "gateways": [],
    "alerts": [],
    "last_poll": None,
    "error": None,
}
_lock = threading.Lock()

# ─── Parse helpers ────────────────────────────────────────────────────────────

def _parse_timestamp(raw) -> str | None:
    """Parse a Timestamp proto bytes/str to ISO string."""
    if not raw:
        return None
    try:
        if isinstance(raw, str):
            raw = raw.encode("latin-1")
        ts = decode_proto(raw)
        seconds = ts.get(1, 0)
        if seconds:
            return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    except Exception:
        pass
    return None

def _parse_location(raw) -> tuple[float, float, float]:
    """Parse a Location proto bytes/str → (lat, lng, alt)."""
    if not raw:
        return 0.0, 0.0, 0.0
    try:
        if isinstance(raw, str):
            raw = raw.encode("latin-1")
        loc = decode_proto(raw)
        return (
            float(loc.get(1, 0.0) or 0.0),
            float(loc.get(2, 0.0) or 0.0),
            float(loc.get(3, 0.0) or 0.0),
        )
    except Exception:
        return 0.0, 0.0, 0.0

def _parse_gateway_list_item(raw_bytes: bytes) -> dict:
    """
    GatewayListItem proto fields:
    1=tenant_id, 2=gateway_id, 3=name, 4=description,
    5=location(bytes), 6=properties(map), 7=created_at(Timestamp bytes),
    8=updated_at(Timestamp bytes), 9=last_seen_at(Timestamp bytes), 10=state(enum)
    """
    gw = decode_proto(raw_bytes)
    state_map = {0: "NEVER_SEEN", 1: "ONLINE", 2: "OFFLINE"}
    lat, lng, alt = _parse_location(gw.get(5))
    return {
        "gateway_id": gw.get(2, ""),
        "name": gw.get(3, gw.get(2, "unknown")),
        "description": gw.get(4, ""),
        "state": state_map.get(int(gw.get(10, 0)), "NEVER_SEEN"),
        "last_seen_at": _parse_timestamp(gw.get(9)),
        "created_at": _parse_timestamp(gw.get(7)),
        "latitude": round(lat, 7),
        "longitude": round(lng, 7),
        "altitude": round(alt, 1),
    }

# ─── ChirpStack API calls ─────────────────────────────────────────────────────

def get_gateways(token: str) -> list:
    """
    ListGatewaysRequest: limit=field1(uint32), offset=field2, search=field3, tenant_id=field4(string)
    ListGatewaysResponse: total_count=field1(uint32), result=field2(repeated bytes)
    """
    body = _intf(1, 1000) + _sf(4, TENANT_ID)
    payload = _grpc_post("/api.GatewayService/List", body, token)
    resp = decode_proto(payload)

    items = resp.get(2, [])
    if not isinstance(items, list):
        items = [items]

    gateways = []
    for item in items:
        if isinstance(item, str):
            item = item.encode("latin-1")
        if isinstance(item, bytes):
            gateways.append(_parse_gateway_list_item(item))
    return gateways

# ─── Polling loop ─────────────────────────────────────────────────────────────

def poll():
    while True:
        try:
            with _lock:
                token = state.get("token")
            if not token:
                time.sleep(5)
                continue

            gws = get_gateways(token)

            with _lock:
                prev = {g["gateway_id"]: g["state"] for g in state["gateways"]}
                state["gateways"] = gws
                state["last_poll"] = datetime.now(timezone.utc).isoformat()
                state["error"] = None

                for gw in gws:
                    gid = gw["gateway_id"]
                    prev_s = prev.get(gid)
                    curr_s = gw["state"]

                    if prev_s == "ONLINE" and curr_s == "OFFLINE":
                        alert = {
                            "type": "OFFLINE",
                            "gateway_id": gid,
                            "name": gw["name"],
                            "time": datetime.now(timezone.utc).isoformat(),
                            "message": f"Gateway '{gw['name']}' ({gid}) se DESCONECTÓ",
                        }
                        state["alerts"].insert(0, alert)
                        state["alerts"] = state["alerts"][:100]
                        log.warning(f"🔴 ALERT: {alert['message']}")
                        threading.Thread(target=send_email_alert, args=(alert,), daemon=True).start()

                    elif prev_s == "OFFLINE" and curr_s == "ONLINE":
                        alert = {
                            "type": "ONLINE",
                            "gateway_id": gid,
                            "name": gw["name"],
                            "time": datetime.now(timezone.utc).isoformat(),
                            "message": f"Gateway '{gw['name']}' ({gid}) volvió en LÍNEA",
                        }
                        state["alerts"].insert(0, alert)
                        state["alerts"] = state["alerts"][:100]
                        log.info(f"🟢 RECOVERY: {alert['message']}")
                        threading.Thread(target=send_email_alert, args=(alert,), daemon=True).start()

        except Exception as e:
            log.error(f"Poll error: {e}")
            with _lock:
                state["error"] = str(e)

        time.sleep(POLL_INTERVAL)

# ─── Auth ─────────────────────────────────────────────────────────────────────

def grpc_login(email: str, password: str) -> str:
    body = _sf(1, email) + _sf(2, password)
    payload = _grpc_post("/api.InternalService/Login", body, token="")
    fields = decode_proto(payload)
    jwt = fields.get(1, "")
    if not jwt:
        raise RuntimeError("Login fallido — token vacío en respuesta")
    return jwt

# ─── REST endpoints ───────────────────────────────────────────────────────────

class LoginBody(BaseModel):
    email: str
    password: str

class ApiKeyBody(BaseModel):
    api_key: str

@app.post("/auth/login")
def api_login(body: LoginBody):
    try:
        jwt = grpc_login(body.email, body.password)
        with _lock:
            state["token"] = jwt
            state["error"] = None
        return {"ok": True}
    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/auth/apikey")
def api_set_key(body: ApiKeyBody):
    with _lock:
        state["token"] = body.api_key
        state["error"] = None
    return {"ok": True}

@app.get("/gateways")
def api_gateways():
    with _lock:
        return {
            "gateways": state["gateways"],
            "last_poll": state["last_poll"],
            "error": state["error"],
        }

@app.get("/alerts")
def api_alerts():
    with _lock:
        return {"alerts": state["alerts"]}

@app.delete("/alerts")
def api_clear_alerts():
    with _lock:
        state["alerts"] = []
    return {"ok": True}

@app.get("/status")
def api_status():
    with _lock:
        total = len(state["gateways"])
        online = sum(1 for g in state["gateways"] if g["state"] == "ONLINE")
        offline = sum(1 for g in state["gateways"] if g["state"] == "OFFLINE")
        never = sum(1 for g in state["gateways"] if g["state"] == "NEVER_SEEN")
        return {
            "authenticated": bool(state["token"]),
            "total": total,
            "online": online,
            "offline": offline,
            "never_seen": never,
            "last_poll": state["last_poll"],
            "error": state["error"],
        }

class EmailConfigBody(BaseModel):
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str
    smtp_password: str
    email_from: str
    email_to: str  # comma-separated for multiple recipients

@app.post("/email/config")
def api_email_config(body: EmailConfigBody):
    global EMAIL_FROM, EMAIL_TO, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD
    SMTP_HOST     = body.smtp_host
    SMTP_PORT     = body.smtp_port
    SMTP_USER     = body.smtp_user
    SMTP_PASSWORD = body.smtp_password
    EMAIL_FROM    = body.email_from
    EMAIL_TO      = body.email_to
    return {"ok": True}

@app.get("/email/config")
def api_get_email_config():
    return {
        "configured": bool(SMTP_USER and SMTP_PASSWORD and EMAIL_TO),
        "smtp_host": SMTP_HOST,
        "smtp_port": SMTP_PORT,
        "smtp_user": SMTP_USER,
        "email_from": EMAIL_FROM,
        "email_to": EMAIL_TO,
        "smtp_password": "***" if SMTP_PASSWORD else "",
    }

@app.post("/email/test")
def api_test_email():
    if not all([EMAIL_FROM, EMAIL_TO, SMTP_USER, SMTP_PASSWORD]):
        raise HTTPException(400, "Email no configurado. Configura SMTP primero.")
    test_alert = {
        "type": "OFFLINE",
        "gateway_id": "test-000000000000",
        "name": "Gateway de Prueba",
        "time": datetime.now(timezone.utc).isoformat(),
        "message": "Este es un correo de prueba del Gateway Monitor",
    }
    try:
        send_email_alert(test_alert)
        return {"ok": True, "message": f"Email de prueba enviado a {EMAIL_TO}"}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/")
def root():
    return FileResponse(os.path.join(BASE_DIR, "index.html"))


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 7070))
    uvicorn.run(app, host="0.0.0.0", port=port, reload=False)
