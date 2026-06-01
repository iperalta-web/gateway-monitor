"""
ChirpStack Gateway Monitor — Backend
Connects to ChirpStack via gRPC-web and serves a REST API for the dashboard.
"""
import hashlib
import hmac
import json
import os
import secrets
import smtplib
import struct
import threading
import time
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests as http_requests
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("gw-monitor")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CHIRPSTACK_URL   = "https://chripstack.0giotsolutions.com"
TENANT_ID        = "4bafa68e-9663-4fc9-931e-6356266d0efe"
CHIRPSTACK_KEY   = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJjaGlycHN0YWNrIiwiaXNzIjoiY2hpcnBzdGFjayIsInN1YiI6Ijg1M2E0ZTFjLTY1OGEtNDRhNy04MGI4LWJhNjJhZGVhYzJkOCIsInR5cCI6ImtleSJ9.QBJ1ew9RY3syb-jHS2DbzEUXjLu6sHdoLnfulH4EFn8"
POLL_INTERVAL    = 30
TOKEN_SECRET     = os.environ.get("TOKEN_SECRET", secrets.token_hex(32))
SESSION_HOURS    = 8

# ─── Email config ──────────────────────────────────────────────────────────────
EMAIL_FROM    = os.environ.get("EMAIL_FROM", "")
EMAIL_TO      = os.environ.get("EMAIL_TO", "")
SMTP_HOST     = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER     = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")

# ─── User store (in-memory, seeded from env) ──────────────────────────────────
# users = { username: { "password_hash": str, "role": "admin"|"viewer", "name": str } }
ADMIN_USER     = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

users_db: dict = {
    ADMIN_USER: {
        "password_hash": _hash(ADMIN_PASSWORD),
        "role": "admin",
        "name": "Administrador",
    }
}

# active sessions: { token: { "username": str, "expires": datetime } }
sessions: dict = {}
_sessions_lock = threading.Lock()

def create_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)
    with _sessions_lock:
        sessions[token] = {"username": username, "expires": expires}
    return token

def get_session_user(token: str) -> dict | None:
    with _sessions_lock:
        s = sessions.get(token)
        if not s:
            return None
        if datetime.now(timezone.utc) > s["expires"]:
            del sessions[token]
            return None
        return {"username": s["username"], **users_db.get(s["username"], {})}

security = HTTPBearer(auto_error=False)

def require_auth(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(401, "No autenticado")
    user = get_session_user(credentials.credentials)
    if not user:
        raise HTTPException(401, "Sesión expirada o inválida")
    return user

def require_admin(user=Depends(require_auth)):
    if user.get("role") != "admin":
        raise HTTPException(403, "Se requiere rol de administrador")
    return user

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
            except Exception: decoded = val
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
    grpc_msg    = r.headers.get("Grpc-Message", "")
    if grpc_status not in ("", "0"):
        raise RuntimeError(f"gRPC {grpc_status}: {grpc_msg}")
    if len(r.content) < 5:
        return b""
    length = struct.unpack(">I", r.content[1:5])[0]
    return r.content[5:5 + length]

# ─── Gateway state ────────────────────────────────────────────────────────────

state = {
    "gateways": [],
    "alerts": [],
    "last_poll": None,
    "error": None,
}
_lock = threading.Lock()

# ─── Parse helpers ─────────────────────────────────────────────────────────────

def _parse_timestamp(raw) -> str | None:
    if not raw: return None
    try:
        if isinstance(raw, str): raw = raw.encode("latin-1")
        ts = decode_proto(raw)
        seconds = ts.get(1, 0)
        if seconds:
            return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    except Exception: pass
    return None

def _parse_location(raw) -> tuple:
    if not raw: return 0.0, 0.0, 0.0
    try:
        if isinstance(raw, str): raw = raw.encode("latin-1")
        loc = decode_proto(raw)
        return (float(loc.get(1, 0.0) or 0.0),
                float(loc.get(2, 0.0) or 0.0),
                float(loc.get(3, 0.0) or 0.0))
    except Exception: return 0.0, 0.0, 0.0

def _parse_gateway_item(raw_bytes: bytes) -> dict:
    gw = decode_proto(raw_bytes)
    state_map = {0: "NEVER_SEEN", 1: "ONLINE", 2: "OFFLINE"}
    lat, lng, alt = _parse_location(gw.get(5))
    return {
        "gateway_id":   gw.get(2, ""),
        "name":         gw.get(3, gw.get(2, "unknown")),
        "description":  gw.get(4, ""),
        "state":        state_map.get(int(gw.get(10, 0)), "NEVER_SEEN"),
        "last_seen_at": _parse_timestamp(gw.get(9)),
        "created_at":   _parse_timestamp(gw.get(7)),
        "latitude":     round(lat, 7),
        "longitude":    round(lng, 7),
        "altitude":     round(alt, 1),
    }

def get_gateways() -> list:
    body    = _intf(1, 1000) + _sf(4, TENANT_ID)
    payload = _grpc_post("/api.GatewayService/List", body, CHIRPSTACK_KEY)
    resp    = decode_proto(payload)
    items   = resp.get(2, [])
    if not isinstance(items, list): items = [items]
    result  = []
    for item in items:
        if isinstance(item, str): item = item.encode("latin-1")
        if isinstance(item, bytes): result.append(_parse_gateway_item(item))
    return result

# ─── Email alerts ──────────────────────────────────────────────────────────────

def send_email_alert(alert: dict):
    if not all([EMAIL_FROM, EMAIL_TO, SMTP_USER, SMTP_PASSWORD]):
        return
    try:
        is_offline = alert["type"] == "OFFLINE"
        subject = f"{'🔴 Gateway DESCONECTADO' if is_offline else '🟢 Gateway RECONECTADO'}: {alert['name']}"
        ts = datetime.fromisoformat(alert["time"]).strftime("%d/%m/%Y %H:%M:%S UTC")
        color = "#f85149" if is_offline else "#56d364"
        bg    = "#1f0d0d" if is_offline else "#0d1f0d"
        bc    = "#da3633" if is_offline else "#238636"
        label = "OFFLINE" if is_offline else "ONLINE"
        tip   = ("Este gateway dejó de reportar. Verifica la conexión física y de red."
                 if is_offline else
                 "El gateway ha vuelto a estar en línea y reportando correctamente.")
        html = f"""<html><body style="font-family:sans-serif;background:#0f1117;color:#e1e4e8;padding:24px">
          <div style="max-width:500px;margin:auto;background:#161b22;border:1px solid #30363d;border-radius:10px;overflow:hidden">
            <div style="background:{bg};border-bottom:1px solid {bc};padding:16px 24px">
              <h2 style="margin:0;color:{color}">{'🔴 Gateway Desconectado' if is_offline else '🟢 Gateway Reconectado'}</h2>
            </div>
            <div style="padding:24px">
              <table style="width:100%;border-collapse:collapse">
                <tr><td style="color:#8b949e;padding:6px 0;width:130px">Gateway</td><td style="font-weight:600">{alert['name']}</td></tr>
                <tr><td style="color:#8b949e;padding:6px 0">ID</td><td style="font-family:monospace;font-size:.9em">{alert['gateway_id']}</td></tr>
                <tr><td style="color:#8b949e;padding:6px 0">Estado</td><td style="color:{color};font-weight:700">{label}</td></tr>
                <tr><td style="color:#8b949e;padding:6px 0">Hora</td><td>{ts}</td></tr>
              </table>
              <div style="margin-top:20px;padding:12px;background:#0d1117;border-radius:6px;font-size:.85em;color:#8b949e">{tip}</div>
            </div>
          </div></body></html>"""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = EMAIL_FROM
        msg["To"]      = EMAIL_TO
        msg.attach(MIMEText(alert["message"], "plain"))
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.ehlo(); smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.sendmail(EMAIL_FROM, EMAIL_TO.split(","), msg.as_string())
        log.info(f"Email enviado: {subject}")
    except Exception as e:
        log.error(f"Error enviando email: {e}")

# ─── Polling loop ──────────────────────────────────────────────────────────────

def poll():
    while True:
        try:
            gws = get_gateways()
            with _lock:
                prev = {g["gateway_id"]: g["state"] for g in state["gateways"]}
                state["gateways"] = gws
                state["last_poll"] = datetime.now(timezone.utc).isoformat()
                state["error"] = None
                for gw in gws:
                    gid    = gw["gateway_id"]
                    prev_s = prev.get(gid)
                    curr_s = gw["state"]
                    if prev_s == "ONLINE" and curr_s == "OFFLINE":
                        alert = {"type":"OFFLINE","gateway_id":gid,"name":gw["name"],
                                 "time":datetime.now(timezone.utc).isoformat(),
                                 "message":f"Gateway '{gw['name']}' ({gid}) se DESCONECTÓ"}
                        state["alerts"].insert(0, alert)
                        state["alerts"] = state["alerts"][:100]
                        log.warning(f"🔴 {alert['message']}")
                        threading.Thread(target=send_email_alert, args=(alert,), daemon=True).start()
                    elif prev_s == "OFFLINE" and curr_s == "ONLINE":
                        alert = {"type":"ONLINE","gateway_id":gid,"name":gw["name"],
                                 "time":datetime.now(timezone.utc).isoformat(),
                                 "message":f"Gateway '{gw['name']}' ({gid}) volvió en LÍNEA"}
                        state["alerts"].insert(0, alert)
                        state["alerts"] = state["alerts"][:100]
                        log.info(f"🟢 {alert['message']}")
                        threading.Thread(target=send_email_alert, args=(alert,), daemon=True).start()
        except Exception as e:
            log.error(f"Poll error: {e}")
            with _lock: state["error"] = str(e)
        time.sleep(POLL_INTERVAL)

# ─── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    t = threading.Thread(target=poll, daemon=True)
    t.start()
    log.info("Polling thread started")
    log.info(f"Admin user: {ADMIN_USER}")
    yield

app = FastAPI(title="Gateway Monitor", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ─── Auth endpoints ────────────────────────────────────────────────────────────

class LoginBody(BaseModel):
    username: str
    password: str

@app.post("/auth/login")
def api_login(body: LoginBody):
    user = users_db.get(body.username)
    if not user or user["password_hash"] != _hash(body.password):
        raise HTTPException(401, "Usuario o contraseña incorrectos")
    token = create_session(body.username)
    return {"token": token, "role": user["role"], "name": user["name"]}

@app.post("/auth/logout")
def api_logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials:
        with _sessions_lock:
            sessions.pop(credentials.credentials, None)
    return {"ok": True}

@app.get("/auth/me")
def api_me(user=Depends(require_auth)):
    return {"username": user["username"], "role": user["role"], "name": user["name"]}

# ─── User management (admin only) ─────────────────────────────────────────────

class UserBody(BaseModel):
    username: str
    password: str
    name: str = ""
    role: str = "viewer"

class ChangePasswordBody(BaseModel):
    old_password: str
    new_password: str

@app.get("/admin/users")
def api_list_users(user=Depends(require_admin)):
    return [
        {"username": u, "name": d["name"], "role": d["role"]}
        for u, d in users_db.items()
    ]

@app.post("/admin/users")
def api_create_user(body: UserBody, user=Depends(require_admin)):
    if body.username in users_db:
        raise HTTPException(400, f"El usuario '{body.username}' ya existe")
    if body.role not in ("admin", "viewer"):
        raise HTTPException(400, "Rol inválido. Usa 'admin' o 'viewer'")
    if len(body.password) < 6:
        raise HTTPException(400, "La contraseña debe tener al menos 6 caracteres")
    users_db[body.username] = {
        "password_hash": _hash(body.password),
        "role": body.role,
        "name": body.name or body.username,
    }
    log.info(f"Usuario creado: {body.username} ({body.role}) por {user['username']}")
    return {"ok": True, "message": f"Usuario '{body.username}' creado"}

@app.delete("/admin/users/{username}")
def api_delete_user(username: str, user=Depends(require_admin)):
    if username == ADMIN_USER:
        raise HTTPException(400, "No se puede eliminar el administrador principal")
    if username not in users_db:
        raise HTTPException(404, "Usuario no encontrado")
    users_db.pop(username)
    # invalidate sessions
    with _sessions_lock:
        to_remove = [t for t, s in sessions.items() if s["username"] == username]
        for t in to_remove: del sessions[t]
    return {"ok": True}

@app.put("/admin/users/{username}/password")
def api_reset_password(username: str, body: dict, user=Depends(require_admin)):
    if username not in users_db:
        raise HTTPException(404, "Usuario no encontrado")
    new_pwd = body.get("password", "")
    if len(new_pwd) < 6:
        raise HTTPException(400, "Mínimo 6 caracteres")
    users_db[username]["password_hash"] = _hash(new_pwd)
    return {"ok": True}

# ─── Gateway data (protected) ─────────────────────────────────────────────────

@app.get("/gateways")
def api_gateways(user=Depends(require_auth)):
    with _lock:
        return {"gateways": state["gateways"], "last_poll": state["last_poll"], "error": state["error"]}

@app.get("/alerts")
def api_alerts(user=Depends(require_auth)):
    with _lock: return {"alerts": state["alerts"]}

@app.delete("/alerts")
def api_clear_alerts(user=Depends(require_admin)):
    with _lock: state["alerts"] = []
    return {"ok": True}

@app.get("/status")
def api_status():
    with _lock:
        total   = len(state["gateways"])
        online  = sum(1 for g in state["gateways"] if g["state"] == "ONLINE")
        offline = sum(1 for g in state["gateways"] if g["state"] == "OFFLINE")
        never   = sum(1 for g in state["gateways"] if g["state"] == "NEVER_SEEN")
        return {"total": total, "online": online, "offline": offline, "never_seen": never,
                "last_poll": state["last_poll"], "error": state["error"]}

# ─── Email config (admin only) ────────────────────────────────────────────────

class EmailConfigBody(BaseModel):
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str
    smtp_password: str
    email_from: str
    email_to: str

@app.post("/email/config")
def api_email_config(body: EmailConfigBody, user=Depends(require_admin)):
    global EMAIL_FROM, EMAIL_TO, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD
    SMTP_HOST = body.smtp_host; SMTP_PORT = body.smtp_port
    SMTP_USER = body.smtp_user; SMTP_PASSWORD = body.smtp_password
    EMAIL_FROM = body.email_from; EMAIL_TO = body.email_to
    return {"ok": True}

@app.get("/email/config")
def api_get_email_config(user=Depends(require_admin)):
    return {"configured": bool(SMTP_USER and SMTP_PASSWORD and EMAIL_TO),
            "smtp_host": SMTP_HOST, "smtp_port": SMTP_PORT,
            "smtp_user": SMTP_USER, "email_from": EMAIL_FROM,
            "email_to": EMAIL_TO, "smtp_password": "***" if SMTP_PASSWORD else ""}

@app.post("/email/test")
def api_test_email(user=Depends(require_admin)):
    if not all([EMAIL_FROM, EMAIL_TO, SMTP_USER, SMTP_PASSWORD]):
        raise HTTPException(400, "Email no configurado")
    test_alert = {"type":"OFFLINE","gateway_id":"test-000","name":"Gateway de Prueba",
                  "time": datetime.now(timezone.utc).isoformat(),
                  "message": "Correo de prueba del Gateway Monitor"}
    try:
        send_email_alert(test_alert)
        return {"ok": True, "message": f"Email enviado a {EMAIL_TO}"}
    except Exception as e:
        raise HTTPException(500, str(e))

# ─── Static ────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return FileResponse(os.path.join(BASE_DIR, "index.html"))

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 7070))
    uvicorn.run(app, host="0.0.0.0", port=port, reload=False)
