from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from crypto.identity import load_or_generate_identity_key
from server.discovery import PasaDiscovery
from server.routes_pairing import router as pairing_router
from server.routes_transfer import router as transfer_router
from server.ws_manager import ws_manager

MAC_IDENTITY_KEY = None
MAC_PUBLIC_KEY = None
discovery = PasaDiscovery()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global MAC_IDENTITY_KEY, MAC_PUBLIC_KEY

    Path("storage").mkdir(exist_ok=True)
    Path("static").mkdir(exist_ok=True)

    # Cargar o generar identidad permanente del receptor
    storage_path = Path("storage/mac_identity.pem")
    MAC_IDENTITY_KEY = load_or_generate_identity_key(storage_path)
    MAC_PUBLIC_KEY = MAC_IDENTITY_KEY.public_key()

    app.state.mac_identity_key = MAC_IDENTITY_KEY
    app.state.mac_public_key = MAC_PUBLIC_KEY

    print("🔐 Identidad P-256 de la Mac lista")
    await discovery.start(port=8000)

    yield

    await discovery.stop()


app = FastAPI(title="Pasa Backend", version="1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Endpoint WebSocket para eventos reactivos en el frontend
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


# Archivos estáticos e interfaz de usuario
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def serve_ui():
    index_file = Path("static/index.html")
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "Pasa Backend en ejecución. Falta static/index.html."}


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "pasa-mac-backend"}


# Registrar routers
app.include_router(pairing_router)
app.include_router(transfer_router)