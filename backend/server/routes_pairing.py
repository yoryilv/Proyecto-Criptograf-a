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

    state.pending_pairings[req.device_id] = {
        "public_key_bytes": android_pub_bytes,
        "sas_code": sas_code,
        "timestamp": req.timestamp,
    }

    # Emitir evento al frontend de la Mac para desplegar el modal
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
    # Si no hay solicitud pendiente de vinculación
    if req.device_id not in state.pending_pairings:
        if req.device_id in state.trusted_devices and req.confirmed:
            return PairConfirmResponse(paired=True, status="trusted")
        raise HTTPException(
            status_code=404,
            detail="No hay vinculación pendiente para este dispositivo",
        )

    if not req.confirmed:
        del state.pending_pairings[req.device_id]
        return PairConfirmResponse(paired=False, status="rejected")

    # Si hay un pairing pendiente aprobado, sobrescribe con la clave pública recién negociada
    pending = state.pending_pairings.pop(req.device_id)
    state.trusted_devices[req.device_id] = pending["public_key_bytes"]

    await ws_manager.broadcast(
        {"type": "PAIRING_SUCCESS", "device_id": req.device_id}
    )

    return PairConfirmResponse(paired=True, status="trusted")


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
        await ws_manager.broadcast(
            {"type": "PAIRING_SUCCESS", "device_id": req.device_id}
        )
        return {"status": "trusted"}
    else:
        state.pending_pairings.pop(req.device_id, None)
        await ws_manager.broadcast(
            {"type": "PAIRING_REJECTED", "device_id": req.device_id}
        )
        return {"status": "rejected"}