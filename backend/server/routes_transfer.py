import base64
from pathlib import Path
from fastapi import APIRouter, Header, HTTPException, Request
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
from crypto.symmetric import decrypt_stream
from server import state
from server.ws_manager import ws_manager

router = APIRouter(prefix="/api/v1/transfer", tags=["Transfer"])


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


@router.post("/request", response_model=TransferRequestRes)
async def transfer_request(req: TransferRequestReq):
    if req.device_id not in state.trusted_devices:
        raise HTTPException(
            status_code=403,
            detail="Dispositivo no emparejado. Realice el pairing primero.",
        )

    enc_path = Path(f"storage/{req.transfer_id}.enc.tmp")
    dec_path = Path(f"storage/{req.transfer_id}.pasa.tmp")

    # Limpiar posibles restos de sesiones previas interrumpidas
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

    # 1. Recuperar clave pública de identidad del cliente previamente validada
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
    print(f"🌱 Clave Efímera Android (E_A, 65 bytes):")
    print(f"   {peer_eph_bytes.hex()[:32]}...{peer_eph_bytes.hex()[-16:]}")
    print(f"✍️ Firma digital ECDSA enviada sobre E_A:")
    print(f"   r: {req.signature_r[:28]}...")
    print(f"   s: {req.signature_s[:28]}...")
    print(f"🔍 Ejecutando verificación: ECDSA_Verify(P_A_permanente, E_A, (r, s))")

    if not is_valid:
        print("❌ RESULTADO: FIRMA INVÁLIDA. CLAVE EFÍMERA NO AUTÉNTICA. POSIBLE MITM.")
        print("=" * 65 + "\n")
        raise HTTPException(
            status_code=401, detail="Firma de handshake inválida (posible MITM)"
        )

    print("✅ RESULTADO: FIRMA AUTÉNTICA. Probada la propiedad de la clave privada de Android.")

    # 4. Generar par efímero local y firmarlo
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
    print(f"🗝️ Clave simétrica de sesión K_AES (HKDF-SHA256, 256 bits):")
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

    # Acumular el flujo binario cifrado (LFSS)
    with open(tx["enc_path"], "ab") as f:
        f.write(chunk_bytes)

    # Notificar progreso en tiempo real al frontend
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
    final_path = Path(f"storage/{tx['file_name']}")

    try:
        # Descifrar el flujo completo con la máquina de estados LFSS
        with open(enc_file, "rb") as src, open(tmp_file, "wb") as dst:
            decrypt_stream(src, dst, tx["session_key"])

        # Verificar integridad SHA-256 en disco
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