import os
import ipaddress
from typing import Optional, List
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
    title="Professional Audit API",
    description="API sécurisée pour l'audit de transactions via Railway",
    version="1.0.0"
)

# --- WebSocket Management ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                # Handle stale connections
                continue

manager = ConnectionManager()

# --- Endpoints ---
@app.get("/")
async def root():
    return {
        "message": "Bienvenue sur l'API Professional Audit",
        "status": "online",
        "documentation": "/docs",
        "checkout": "/checkout",
        "admin_panel": "/panel"
    }

@app.get("/checkout")
async def get_checkout():
    return FileResponse("checkout.html")

@app.get("/panel")
async def get_panel():
    return FileResponse("panel.html")

# --- Security ---
async def get_api_key(
    header_key: Optional[str] = Security(api_key_header)
):
    if header_key == API_KEY:
        return header_key
    raise HTTPException(
        status_code=HTTP_403_FORBIDDEN, detail="Invalid API Key"
    )

# --- Models ---
class AuditRequest(BaseModel):
    email: EmailStr
    montant: float = Field(..., gt=0, description="Montant de la transaction")
    numero_carte_masque: str = Field(..., pattern=r"^\d{4}-\*{4}-\*{4}-\d{4}$")
    adresse_ip: str

    @field_validator("adresse_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError("Format d'adresse IP invalide")

class AuditResponse(BaseModel):
    email: str
    risk_score: int
    status: str
    message: str

# --- Logic ---
def calculate_risk(montant: float, ip: str) -> int:
    score = 0
    
    # Règle 1: Montant élevé
    if montant > 1000:
        score += 50
    elif montant > 500:
        score += 20
        
    # Règle 2: IP Validation (déjà validé par Pydantic, mais on peut ajouter des pays bannis etc.)
    # Ici on simule une IP suspecte (ex: commence par 192.168 qui est local)
    if ip.startswith("192.168"):
        score += 30
        
    return min(score, 100)

# --- Endpoints ---
@app.post("/v1/audit", response_model=AuditResponse)
async def create_audit(
    request: AuditRequest, 
    api_key: APIKey = Depends(get_api_key)
):
    risk_score = calculate_risk(request.montant, request.adresse_ip)
    status = "APPROVED" if risk_score < 40 else "REVIEW" if risk_score < 75 else "REJECTED"
    
    response_data = AuditResponse(
        email=request.email,
        risk_score=risk_score,
        status=status,
        message=f"Transaction traitée avec succès. Résultat: {status}"
    )

    # Broadcast to admin panel
    audit_data = request.dict()
    audit_data["risk_score"] = risk_score
    audit_data["status"] = status
    await manager.broadcast(audit_data)
    
    return response_data

@app.websocket("/ws/admin")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "port": os.getenv("PORT", "8000")}

# --- Entry Point ---
if __name__ == "__main__":
    import uvicorn
    # Railway injecte la variable PORT
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
