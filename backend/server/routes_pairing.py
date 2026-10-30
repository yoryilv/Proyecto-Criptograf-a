import asyncio
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from crypto.identity import (
    base64_to_public_key,
    compute_sas,
    public_key_to_base64,
    public_key_to_uncompressed_bytes,
)
from server import state
from server.ws_manager import ws_manager

router = APIRouter(prefix="/api/v1/pair", tags=["Pairing"])


class PairInitRequest(BaseModel):
    device_id: str
    identity_public_key: str
    timestamp: int


class PairInitResponse(BaseModel):
    device_id: str
    identity_public_key: str
    sas_code: str
    status: str


class PairConfirmRequest(BaseModel):
    device_id: str
    confirmed: bool


class PairConfirmResponse(BaseModel):
    paired: bool
    status: str


class WebDecisionRequest(BaseModel):
    device_id: str
    approved: bool


@router.post("/init", response_model=PairInitResponse)
async def init_pairing(req: PairInitRequest, request: Request):
    try:
        android_pub_key = base64_to_public_key(req.identity_public_key)
        android_pub_bytes = public_key_to_uncompressed_bytes(android_pub_key)
    except Exception:
        raise HTTPException(
            status_code=400, detail="Clave pública P-256 inválida o corrupta"
        )

    mac_pub_key = request.app.state.mac_public_key
    mac_pub_bytes = public_key_to_uncompressed_bytes(mac_pub_key)

    # Cálculo simétrico del código visual de 6 dígitos
    sas_code = compute_sas(mac_pub_bytes, android_pub_bytes)

    # Forzar que un re-emparejamiento requiera confirmación humana nuevamente
    state.trusted_devices.pop(req.device_id, None)

    # --- AUDITORÍA CRIPTOGRÁFICA: EMPAREJAMIENTO SAS ---
    print("\n" + "=" * 65)
    print("🛡️ [PASO 1: EMPAREJAMIENTO DE IDENTIDAD - PROTOCOLO SAS]")
    print(f"📱 Dispositivo cliente: {req.device_id}")
    print(f"🔑 Clave Pública Android (P_A, 65 bytes ANSI X9.62):")
    print(f"   {android_pub_bytes.hex()[:32]}...{android_pub_bytes.hex()[-16:]}")
    print(f"🔑 Clave Pública Mac     (P_B, 65 bytes ANSI X9.62):")
    print(f"   {mac_pub_bytes.hex()[:32]}...{mac_pub_bytes.hex()[-16:]}")
    print(f"🧮 Hash determinista: SHA-256(min(P_A, P_B) || max(P_A, P_B))")
    print(f"🔢 Código SAS resultante (Out-of-Band): >> {sas_code} <<")
    print("=" * 65 + "\n")

    state.pending_pairings[req.device_id] = {
        "public_key_bytes": android_pub_bytes,
        "sas_code": sas_code,
        "timestamp": req.timestamp,
    }

    # Emitir evento al frontend de la Mac para desplegar el modal interactivo
    await ws_manager.broadcast(
        {
            "type": "PAIRING_REQUEST",
            "device_id": req.device_id,
            "sas_code": sas_code,
        }
    )

    return PairInitResponse(
        device_id="MacBook-Pro-de-Matias",
        identity_public_key=public_key_to_base64(mac_pub_key),
        sas_code=sas_code,
        status="pending_user_confirmation",
    )


@router.post("/confirm", response_model=PairConfirmResponse)
async def confirm_pairing(req: PairConfirmRequest):
    if not req.confirmed:
        state.pending_pairings.pop(req.device_id, None)
        print(f"❌ Emparejamiento cancelado desde el dispositivo: '{req.device_id}'")
        await ws_manager.broadcast(
            {"type": "PAIRING_REJECTED", "device_id": req.device_id}
        )
        return PairConfirmResponse(paired=False, status="rejected")

    # Si ya está verificado en la lista blanca por una acción previa
    if req.device_id in state.trusted_devices:
        return PairConfirmResponse(paired=True, status="trusted")

    if req.device_id not in state.pending_pairings:
        raise HTTPException(
            status_code=404,
            detail="No hay vinculación pendiente para este dispositivo",
        )

    print(f"⏳ Dispositivo '{req.device_id}' esperando confirmación en la Web de la Mac...")

    # Bucle de espera: Retiene la petición HTTP de Android hasta que tú pulses el botón en la Mac
    timeout_seconds = 45
    elapsed = 0.0
    while elapsed < timeout_seconds:
        # 1. Aprobado desde la interfaz web (web_decision lo agregó a trusted_devices)
        if req.device_id in state.trusted_devices:
            print(f"✅ Confirmación humana recibida. '{req.device_id}' vinculado.")
            return PairConfirmResponse(paired=True, status="trusted")

        # 2. Rechazado desde la interfaz web (web_decision lo eliminó de pending_pairings)
        if req.device_id not in state.pending_pairings:
            print(f"❌ Rechazado desde la interfaz web para '{req.device_id}'.")
            return PairConfirmResponse(paired=False, status="rejected")

        await asyncio.sleep(0.5)
        elapsed += 0.5

    # 3. Expiración de tiempo
    state.pending_pairings.pop(req.device_id, None)
    print(f"⏱️ Tiempo de espera agotado para emparejar '{req.device_id}'.")
    await ws_manager.broadcast(
        {"type": "PAIRING_REJECTED", "device_id": req.device_id}
    )
    raise HTTPException(status_code=408, detail="Tiempo de espera agotado sin confirmación humana")


@router.post("/web-decision")
async def web_decision(req: WebDecisionRequest):
    """Acción invocada desde los botones de la pantalla en la Mac."""
    if req.device_id not in state.pending_pairings:
        raise HTTPException(
            status_code=404, detail="Solicitud no encontrada o expirada"
        )

    if req.approved:
        pending = state.pending_pairings.pop(req.device_id)
        state.trusted_devices[req.device_id] = pending["public_key_bytes"]
        print(f"✅ Aprobado desde la interfaz web: '{req.device_id}' añadido a trusted_devices.")
        await ws_manager.broadcast(
            {"type": "PAIRING_SUCCESS", "device_id": req.device_id}
        )
        return {"status": "trusted"}
    else:
        state.pending_pairings.pop(req.device_id, None)
        print(f"❌ Rechazado desde la interfaz web: '{req.device_id}' descartado.")
        await ws_manager.broadcast(
            {"type": "PAIRING_REJECTED", "device_id": req.device_id}
        )
        return {"status": "rejected"}