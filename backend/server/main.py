import socket
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
from ble_advertiser import start_ble_beacon_in_background

MAC_IDENTITY_KEY = None
MAC_PUBLIC_KEY = None
discovery = PasaDiscovery()


def get_local_ip() -> str:
    """Obtiene la dirección IPv4 activa de la Mac en la red local."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


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

    local_ip = get_local_ip()

    # 1. Anuncio mDNS / ZeroConf (red local Wi-Fi)
    await discovery.start(port=8000)

    # 2. Baliza BLE de proximidad en segundo plano (Bluetooth)
    try:
        start_ble_beacon_in_background(local_ip, 8000)
    except Exception as e:
        print(f"⚠️ No se pudo iniciar BLE Advertisement: {e}")

    print(f"🚀 Pasa listo en {local_ip}:8000 (mDNS activo + BLE beacon activo)")

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