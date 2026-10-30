import base64
import hashlib
import uuid
import asyncio
from pathlib import Path

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel

from crypto.identity import (
    base64_to_public_key,
    hex_to_rs,
    public_key_to_base64,
    public_key_to_uncompressed_bytes,
    rs_to_hex,
    uncompressed_bytes_to_public_key,
)
from crypto.integrity import verify_file_integrity
from crypto.key_agreement import (
    compute_shared_secret,
    derive_session_key,
    generate_ephemeral_keypair,
    sign_ephemeral_public_key,
    verify_ephemeral_public_key,
)
from crypto.symmetric import decrypt_stream, encrypt_stream
from server import state
from server.ws_manager import ws_manager

router = APIRouter(prefix="/api/v1/transfer", tags=["Transfer"])

pending_inbound_decisions = {}

STORAGE_DIR = Path("storage")
STORAGE_DIR.mkdir(exist_ok=True)

# Inicializar almacenamiento de transferencias salientes (Mac -> Android)
if not hasattr(state, "active_outbound_transfers"):
    state.active_outbound_transfers = {}


def compute_file_sha256(file_path: Path) -> str:
    """Calcula el hash SHA-256 de un archivo en disco por bloques de 64 KiB."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


# ==========================================
# MODELOS DE TRANSFERENCIA ENTRANTE (ANDROID -> MAC)
# ==========================================

class TransferRequestReq(BaseModel):
    device_id: str
    transfer_id: str
    file_name: str
    file_size_bytes: int
    total_chunks: int
    sha256_expected: str


class TransferRequestRes(BaseModel):
    transfer_id: str
    accepted: bool


class HandshakeReq(BaseModel):
    device_id: str
    transfer_id: str
    ephemeral_public_key: str
    signature_r: str
    signature_s: str


class HandshakeRes(BaseModel):
    transfer_id: str
    ephemeral_public_key: str
    signature_r: str
    signature_s: str
    status: str


class FinalizeReq(BaseModel):
    transfer_id: str


class FinalizeRes(BaseModel):
    transfer_id: str
    integrity_valid: bool
    file_path: str
    status: str


class TransferAbortReq(BaseModel):
    transfer_id: str
    reason: str = "user_cancelled"

class InboundDecisionReq(BaseModel):
    transfer_id: str
    accepted: bool

# ==========================================
# RUTAS DE TRANSFERENCIA ENTRANTE (ANDROID -> MAC)
# ==========================================

@router.post("/request", response_model=TransferRequestRes)
async def transfer_request(req: TransferRequestReq):
    if req.device_id not in state.trusted_devices:
        raise HTTPException(
            status_code=403,
            detail="Dispositivo no emparejado. Realice el pairing primero.",
        )

    # 1. Crear evento y registrarlo en espera
    event = asyncio.Event()
    pending_inbound_decisions[req.transfer_id] = {
        "event": event,
        "accepted": False,
    }

    # 2. Notificar al navegador web para abrir el modal de confirmación
    await ws_manager.broadcast(
        {
            "type": "INBOUND_FILE_OFFER",
            "transfer_id": req.transfer_id,
            "device_id": req.device_id,
            "file_name": req.file_name,
            "file_size": req.file_size_bytes,
        }
    )

    print(f"⏳ Archivo '{req.file_name}' entrante de {req.device_id}. Esperando aprobación en la web de la Mac...")

    try:
        # Esperar hasta 60 segundos a la decisión del usuario en la Mac
        await asyncio.wait_for(event.wait(), timeout=60.0)
    except asyncio.TimeoutError:
        pending_inbound_decisions.pop(req.transfer_id, None)
        raise HTTPException(status_code=408, detail="Transferencia expirada sin confirmación")

    decision = pending_inbound_decisions.pop(req.transfer_id, None)
    if not decision or not decision["accepted"]:
        print(f"❌ Transferencia de '{req.file_name}' rechazada desde la interfaz web.")
        raise HTTPException(status_code=403, detail="Transferencia rechazada por el receptor")

    # 3. Preparar recepción tras ser aceptada
    enc_path = STORAGE_DIR / f"{req.transfer_id}.enc.tmp"
    dec_path = STORAGE_DIR / f"{req.transfer_id}.pasa.tmp"

    enc_path.unlink(missing_ok=True)
    dec_path.unlink(missing_ok=True)

    state.active_transfers[req.transfer_id] = {
        "device_id": req.device_id,
        "file_name": req.file_name,
        "file_size": req.file_size_bytes,
        "total_chunks": req.total_chunks,
        "sha256_expected": req.sha256_expected,
        "enc_path": enc_path,
        "tmp_path": dec_path,
        "session_key": None,
    }

    await ws_manager.broadcast(
        {
            "type": "TRANSFER_START",
            "device_id": req.device_id,
            "file_name": req.file_name,
            "file_size": req.file_size_bytes,
            "total_chunks": req.total_chunks,
        }
    )

    return TransferRequestRes(transfer_id=req.transfer_id, accepted=True)


@router.post("/handshake", response_model=HandshakeRes)
async def transfer_handshake(req: HandshakeReq, request: Request):
    tx = state.active_transfers.get(req.transfer_id)
    if not tx:
        raise HTTPException(status_code=404, detail="Transferencia no encontrada")

    # 1. Recuperar clave de identidad permanente del cliente (previniendo MITM)
    peer_identity_bytes = state.trusted_devices.get(req.device_id)
    peer_identity_key = uncompressed_bytes_to_public_key(peer_identity_bytes)

    # 2. Desempaquetar clave efímera y firma (r, s)
    peer_eph_pub_key = base64_to_public_key(req.ephemeral_public_key)
    peer_eph_bytes = public_key_to_uncompressed_bytes(peer_eph_pub_key)
    r, s = hex_to_rs(req.signature_r, req.signature_s)

    # 3. VERIFICACIÓN CRIPTOGRÁFICA ANTI-MITM
    is_valid = verify_ephemeral_public_key(
        peer_identity_key, peer_eph_bytes, r, s
    )

    print("\n" + "=" * 65)
    print("🔒 [PASO 2: HANDSHAKE ECDHE AUTENTICADO - DEFENSA ANTI-MITM]")
    print(f"📦 Transfer ID: {req.transfer_id}")
    print(f"📱 Dispositivo emisor: {req.device_id}")
    print("🌱 Clave Efímera Android (E_A, 65 bytes):")
    print(f"   {peer_eph_bytes.hex()[:32]}...{peer_eph_bytes.hex()[-16:]}")
    print("✍️ Firma digital ECDSA enviada sobre E_A:")
    print(f"   r: {req.signature_r[:28]}...")
    print(f"   s: {req.signature_s[:28]}...")
    print("🔍 Ejecutando verificación: ECDSA_Verify(P_A_permanente, E_A, (r, s))")

    if not is_valid:
        print("❌ RESULTADO: FIRMA INVÁLIDA. CLAVE EFÍMERA NO AUTÉNTICA. POSIBLE MITM.")
        print("=" * 65 + "\n")
        raise HTTPException(
            status_code=401, detail="Firma de handshake inválida (posible MITM)"
        )

    print("✅ RESULTADO: FIRMA AUTÉNTICA. Probada la propiedad de la clave privada de Android.")

    # 4. Generar par efímero local de la Mac y firmarlo
    mac_identity_key = request.app.state.mac_identity_key
    my_eph_priv, my_eph_pub = generate_ephemeral_keypair()
    my_eph_bytes = public_key_to_uncompressed_bytes(my_eph_pub)

    my_r, my_s = sign_ephemeral_public_key(mac_identity_key, my_eph_pub)
    my_r_hex, my_s_hex = rs_to_hex(my_r, my_s)

    # 5. Derivar secreto compartido Z y clave simétrica de sesión K_aes
    shared_secret = compute_shared_secret(my_eph_priv, peer_eph_pub_key)
    k_aes = derive_session_key(shared_secret, my_eph_bytes, peer_eph_bytes)
    tx["session_key"] = k_aes

    print(f"🤝 Secreto compartido ECDH derivado (Z, 32 bytes): {shared_secret.hex()[:24]}...")
    print("🗝️ Clave simétrica de sesión K_AES (HKDF-SHA256, 256 bits):")
    print(f"   {k_aes.hex()[:32]}... (32 bytes)")
    print("=" * 65 + "\n")

    await ws_manager.broadcast(
        {"type": "HANDSHAKE_OK", "transfer_id": req.transfer_id}
    )

    return HandshakeRes(
        transfer_id=req.transfer_id,
        ephemeral_public_key=public_key_to_base64(my_eph_pub),
        signature_r=my_r_hex,
        signature_s=my_s_hex,
        status="ready_for_stream",
    )


@router.post("/chunk")
async def receive_chunk(
    request: Request,
    x_transfer_id: str = Header(...),
    x_chunk_index: int = Header(...),
):
    tx = state.active_transfers.get(x_transfer_id)
    if not tx or not tx["session_key"]:
        raise HTTPException(
            status_code=403,
            detail="Transferencia no válida o handshake incompleto",
        )

    chunk_bytes = await request.body()

    with open(tx["enc_path"], "ab") as f:
        f.write(chunk_bytes)

    progress_pct = int(((x_chunk_index + 1) / tx["total_chunks"]) * 100)
    await ws_manager.broadcast(
        {
            "type": "TRANSFER_PROGRESS",
            "chunk_index": x_chunk_index + 1,
            "total_chunks": tx["total_chunks"],
            "progress": progress_pct,
        }
    )

    return {"transfer_id": x_transfer_id, "chunk_index": x_chunk_index, "status": "ack"}


@router.post("/finalize", response_model=FinalizeRes)
async def transfer_finalize(req: FinalizeReq):
    tx = state.active_transfers.get(req.transfer_id)
    if not tx:
        raise HTTPException(status_code=404, detail="Transferencia no encontrada")

    enc_file = tx["enc_path"]
    tmp_file = tx["tmp_path"]
    final_path = STORAGE_DIR / tx["file_name"]

    try:
        with open(enc_file, "rb") as src, open(tmp_file, "wb") as dst:
            decrypt_stream(src, dst, tx["session_key"])

        is_valid = verify_file_integrity(tmp_file, tx["sha256_expected"])

        print("\n" + "=" * 65)
        print("🔍 [PASO 3: VALIDACIÓN DE INTEGRIDAD EN DESTINO]")
        print(f"📄 Archivo recibido : {tx['file_name']}")
        print(f"🎯 SHA-256 esperado : {tx['sha256_expected']}")
        print(f"🛡️ Verificación en disco : {'✅ SÍ (Íntegro)' if is_valid else '❌ NO (Corrupto/Alterado)'}")
        print("=" * 65 + "\n")

        if is_valid:
            tmp_file.rename(final_path)
            enc_file.unlink(missing_ok=True)
            status_msg = "completed"
        else:
            tmp_file.unlink(missing_ok=True)
            enc_file.unlink(missing_ok=True)
            status_msg = "integrity_failed"

    except Exception as e:
        tmp_file.unlink(missing_ok=True)
        enc_file.unlink(missing_ok=True)
        raise HTTPException(
            status_code=400, detail=f"Fallo de autenticación o formato LFSS: {str(e)}"
        )

    await ws_manager.broadcast(
        {
            "type": "TRANSFER_FINISH",
            "success": is_valid,
            "file_name": tx["file_name"],
            "status": status_msg,
        }
    )

    del state.active_transfers[req.transfer_id]

    return FinalizeRes(
        transfer_id=req.transfer_id,
        integrity_valid=is_valid,
        file_path=str(final_path) if is_valid else "",
        status=status_msg,
    )


# ==========================================
# RUTAS DE TRANSFERENCIA SALIENTE (MAC -> ANDROID)
# ==========================================

class OutboundHandshakeReq(BaseModel):
    transfer_id: str
    device_id: str
    ephemeral_public_key: str
    signature_r: str
    signature_s: str


@router.post("/outbound/init")
async def outbound_init(
    request: Request,
    device_id: str = Header(...),
):
    """La Mac inicia el envío de un archivo hacia un dispositivo emparejado."""
    form = await request.form()
    file = form.get("file")
    if not file:
        raise HTTPException(status_code=400, detail="No se subió ningún archivo")

    if device_id not in state.trusted_devices:
        raise HTTPException(status_code=403, detail="Dispositivo no emparejado")

    transfer_id = str(uuid.uuid4())
    raw_path = STORAGE_DIR / f"out_{transfer_id}.raw.tmp"

    contents = await file.read()
    with open(raw_path, "wb") as f:
        f.write(contents)

    sha256_expected = compute_file_sha256(raw_path)
    file_size = len(contents)

    # Generar par efímero de la Mac y firmarlo con su identidad permanente
    mac_identity_key = request.app.state.mac_identity_key
    mac_eph_priv, mac_eph_pub = generate_ephemeral_keypair()
    mac_eph_bytes = public_key_to_uncompressed_bytes(mac_eph_pub)
    r, s = sign_ephemeral_public_key(mac_identity_key, mac_eph_pub)
    r_hex, s_hex = rs_to_hex(r, s)

    state.active_outbound_transfers[transfer_id] = {
        "device_id": device_id,
        "file_name": file.filename,
        "file_size": file_size,
        "sha256_expected": sha256_expected,
        "raw_path": raw_path,
        "enc_path": STORAGE_DIR / f"out_{transfer_id}.enc",
        "mac_eph_priv": mac_eph_priv,
        "mac_eph_bytes": mac_eph_bytes,
        "session_key": None,
    }

    # Notificar a Android vía WebSocket en tiempo real
    await ws_manager.broadcast({
        "type": "OUTBOUND_TRANSFER_OFFER",
        "transfer_id": transfer_id,
        "target_device_id": device_id,
        "file_name": file.filename,
        "file_size": file_size,
        "sha256_expected": sha256_expected,
        "ephemeral_public_key": base64.b64encode(mac_eph_bytes).decode("ascii"),
        "signature_r": r_hex,
        "signature_s": s_hex,
    })

    return {"status": "offer_sent", "transfer_id": transfer_id}


@router.post("/outbound/handshake")
async def outbound_handshake(req: OutboundHandshakeReq):
    """Android acepta la transferencia y responde con su clave efímera firmada."""
    tx = state.active_outbound_transfers.get(req.transfer_id)
    if not tx:
        raise HTTPException(status_code=404, detail="Transferencia no encontrada")

    # 1. Verificar firma ECDSA de Android
    peer_pub_bytes = state.trusted_devices.get(req.device_id)
    peer_identity_key = uncompressed_bytes_to_public_key(peer_pub_bytes)

    android_eph_pub = base64_to_public_key(req.ephemeral_public_key)
    android_eph_bytes = public_key_to_uncompressed_bytes(android_eph_pub)
    r, s = hex_to_rs(req.signature_r, req.signature_s)

    is_valid = verify_ephemeral_public_key(peer_identity_key, android_eph_bytes, r, s)
    if not is_valid:
        raise HTTPException(status_code=401, detail="Firma de Android inválida (MITM)")

    # 2. Derivar clave simétrica K_session
    shared_secret = compute_shared_secret(tx["mac_eph_priv"], android_eph_pub)
    k_aes = derive_session_key(shared_secret, tx["mac_eph_bytes"], android_eph_bytes)
    tx["session_key"] = k_aes

    # 3. Cifrar archivo con formato de streaming LFSS (AES-256-GCM)
    with open(tx["raw_path"], "rb") as src, open(tx["enc_path"], "wb") as dst:
        encrypt_stream(src, dst, k_aes)

    tx["raw_path"].unlink(missing_ok=True)

    print("\n" + "=" * 65)
    print("📤 [MAC -> ANDROID: CIFRADO LFSS COMPLETADO]")
    print(f"📄 Archivo preparado: {tx['file_name']} ({tx['file_size']} bytes)")
    print(f"🗝️ K_session derivada: {k_aes.hex()[:32]}...")
    print("=" * 65 + "\n")

    return {"status": "ready_to_stream"}


@router.get("/outbound/stream/{transfer_id}")
async def outbound_stream(transfer_id: str):
    """Android descarga el flujo binario cifrado LFSS."""
    tx = state.active_outbound_transfers.get(transfer_id)
    if not tx or not tx["enc_path"].exists():
        raise HTTPException(status_code=404, detail="Flujo cifrado no disponible")

    return FileResponse(
        tx["enc_path"],
        media_type="application/octet-stream",
        filename=f"{tx['file_name']}.enc"
    )


@router.post("/outbound/complete")
async def outbound_complete(transfer_id: str = Header(...)):
    """Android confirma que descifró e integró el archivo en su almacenamiento."""
    tx = state.active_outbound_transfers.pop(transfer_id, None)
    if tx:
        tx["enc_path"].unlink(missing_ok=True)
        await ws_manager.broadcast({
            "type": "TRANSFER_FINISH",
            "success": True,
            "file_name": tx["file_name"],
            "status": "completed",
        })
    return {"status": "ok"}

@router.post("/decision")
async def inbound_decision(req: InboundDecisionReq):
    """El usuario en la web aprueba o rechaza el archivo entrante de Android."""
    item = pending_inbound_decisions.get(req.transfer_id)
    if not item:
        raise HTTPException(status_code=404, detail="Solicitud expirada o no encontrada")

    item["accepted"] = req.accepted
    item["event"].set()
    return {"status": "ok", "accepted": req.accepted}


# ==========================================
# CANCELACIÓN LIMPIA Y ABORTO
# ==========================================

@router.post("/abort")
async def abort_transfer(req: TransferAbortReq):
    """Limpia cualquier rastro en disco si se cancela una transferencia activa."""
    cleaned = False

    if req.transfer_id in state.active_transfers:
        tx = state.active_transfers.pop(req.transfer_id)
        tx["enc_path"].unlink(missing_ok=True)
        tx["tmp_path"].unlink(missing_ok=True)
        cleaned = True

    if req.transfer_id in state.active_outbound_transfers:
        tx = state.active_outbound_transfers.pop(req.transfer_id)
        tx["raw_path"].unlink(missing_ok=True)
        tx["enc_path"].unlink(missing_ok=True)
        cleaned = True

    if cleaned:
        print(f"🧹 Archivos temporales de {req.transfer_id} eliminados ({req.reason}).")
        await ws_manager.broadcast({
            "type": "TRANSFER_ABORTED",
            "transfer_id": req.transfer_id,
            "reason": req.reason,
        })
        return {"status": "cleaned"}

    raise HTTPException(status_code=404, detail="Transferencia no encontrada")