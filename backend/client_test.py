import io
import math
import time
import uuid
from pathlib import Path
import requests

from cryptography.hazmat.primitives.asymmetric import ec

from crypto.identity import (
    base64_to_public_key,
    compute_sas,
    hex_to_rs,
    public_key_to_base64,
    public_key_to_uncompressed_bytes,
    rs_to_hex,
)
from crypto.integrity import compute_file_sha256
from crypto.key_agreement import (
    compute_shared_secret,
    derive_session_key,
    generate_ephemeral_keypair,
    sign_ephemeral_public_key,
    verify_ephemeral_public_key,
)
from crypto.symmetric import encrypt_stream

BASE_URL = "http://127.0.0.1:8000"
DEVICE_ID = "Pixel-8-Simulador"
CHUNK_SIZE = 256 * 1024  # 256 KiB por fragmento de transporte HTTP


def run_simulation():
    print(f"🚀 Iniciando cliente simulador ({DEVICE_ID})...\n")

    # 0. Preparar archivo de prueba
    test_file = Path("test_envio.txt")
    if not test_file.exists():
        test_file.write_text("Contenido confidencial transferido mediante protocolo Pasa con cifrado LFSS.")

    file_bytes_len = test_file.stat().st_size
    file_sha256 = compute_file_sha256(test_file)
    print(f"📄 Archivo preparado: '{test_file.name}' ({file_bytes_len} bytes)")
    print(f"   SHA-256 original: {file_sha256}\n")

    # 1. Identidad permanente simulada de Android (P-256)
    android_id_priv = ec.generate_private_key(ec.SECP256R1())
    android_id_pub = android_id_priv.public_key()
    android_id_bytes = public_key_to_uncompressed_bytes(android_id_pub)
    android_id_b64 = public_key_to_base64(android_id_pub)

    # 2. Paso 1 del Pairing: /pair/init
    print("🤝 [1/5] Solicitando emparejamiento a la Mac...")
    init_payload = {
        "device_id": DEVICE_ID,
        "identity_public_key": android_id_b64,
        "timestamp": int(time.time()),
    }
    res = requests.post(f"{BASE_URL}/api/v1/pair/init", json=init_payload)
    if res.status_code != 200:
        print(f"❌ Error en pair/init: {res.text}")
        return
    pair_init_data = res.json()
    mac_pub_b64 = pair_init_data["identity_public_key"]
    mac_pub = base64_to_public_key(mac_pub_b64)
    mac_pub_bytes = public_key_to_uncompressed_bytes(mac_pub)

    local_sas = compute_sas(android_id_bytes, mac_pub_bytes)
    print(f"   Código SAS calculado: {local_sas}")
    assert local_sas == pair_init_data["sas_code"], "Discrepancia en el cálculo del código SAS"

    # 3. Paso 2 del Pairing: /pair/confirm
    confirm_payload = {"device_id": DEVICE_ID, "confirmed": True}
    res = requests.post(f"{BASE_URL}/api/v1/pair/confirm", json=confirm_payload)
    if res.status_code != 200:
        print(f"❌ Error en pair/confirm: {res.text}")
        return
    print("   Emparejamiento confirmado y guardado en la lista blanca de la Mac.\n")

    # 4. Negociar Transferencia: /transfer/request
    print("📦 [2/5] Solicitando permiso de transferencia...")
    transfer_id = str(uuid.uuid4())

    # Estimación de chunks: tamaño del archivo + sobrecarga de cabeceras LFSS (aprox 1 KB)
    estimated_total_chunks = max(1, math.ceil((file_bytes_len + 1024) / CHUNK_SIZE))

    res = requests.post(
        f"{BASE_URL}/api/v1/transfer/request",
        json={
            "device_id": DEVICE_ID,
            "transfer_id": transfer_id,
            "file_name": test_file.name,
            "file_size_bytes": file_bytes_len,
            "total_chunks": estimated_total_chunks,
            "sha256_expected": file_sha256,
        },
    )
    if res.status_code != 200:
        print(f"❌ Error en transfer/request: {res.text}")
        return

    # 5. Handshake ECDHE: /transfer/handshake
    print("🔑 [3/5] Ejecutando Handshake ECDHE autenticado...")
    eph_priv, eph_pub = generate_ephemeral_keypair()
    eph_pub_bytes = public_key_to_uncompressed_bytes(eph_pub)
    eph_pub_b64 = public_key_to_base64(eph_pub)

    sig_r, sig_s = sign_ephemeral_public_key(android_id_priv, eph_pub)
    r_hex, s_hex = rs_to_hex(sig_r, sig_s)

    handshake_payload = {
        "device_id": DEVICE_ID,
        "transfer_id": transfer_id,
        "ephemeral_public_key": eph_pub_b64,
        "signature_r": r_hex,
        "signature_s": s_hex,
    }

    res = requests.post(f"{BASE_URL}/api/v1/transfer/handshake", json=handshake_payload)
    if res.status_code != 200:
        print(f"❌ Error en handshake: {res.text}")
        return
    hs_data = res.json()

    mac_eph_pub = base64_to_public_key(hs_data["ephemeral_public_key"])
    mac_eph_bytes = public_key_to_uncompressed_bytes(mac_eph_pub)
    mac_r, mac_s = hex_to_rs(hs_data["signature_r"], hs_data["signature_s"])

    valid_mac_sig = verify_ephemeral_public_key(mac_pub, mac_eph_bytes, mac_r, mac_s)
    if not valid_mac_sig:
        print("❌ La firma de la Mac es inválida. Posible ataque MITM.")
        return
    print("   Firma de la Mac verificada con éxito.")

    # Derivar clave de sesión K_AES (256 bits)
    shared_secret = compute_shared_secret(eph_priv, mac_eph_pub)
    k_aes = derive_session_key(shared_secret, eph_pub_bytes, mac_eph_bytes)
    print("   Clave simétrica de sesión K_AES derivada.")

    # 6. Cifrar archivo usando LFSS
    enc_buffer = io.BytesIO()
    with open(test_file, "rb") as f:
        encrypt_stream(f, enc_buffer, k_aes)
    enc_bytes = enc_buffer.getvalue()

    actual_chunks = max(1, math.ceil(len(enc_bytes) / CHUNK_SIZE))

    print(f"\n📤 [4/5] Transmitiendo flujo cifrado LFSS ({len(enc_bytes)} bytes en {actual_chunks} chunk(s))...")
    for i in range(actual_chunks):
        chunk_data = enc_bytes[i * CHUNK_SIZE : (i + 1) * CHUNK_SIZE]
        headers = {
            "Content-Type": "application/octet-stream",
            "X-Transfer-Id": transfer_id,
            "X-Chunk-Index": str(i),
        }
        res = requests.post(f"{BASE_URL}/api/v1/transfer/chunk", data=chunk_data, headers=headers)
        if res.status_code != 200:
            print(f"❌ Error enviando chunk {i}: {res.text}")
            return
        print(f"   Chunk {i + 1}/{actual_chunks} transmitido.")

    # 7. Finalizar y verificar en servidor
    print("\n🏁 [5/5] Finalizando transferencia en el servidor...")
    res = requests.post(f"{BASE_URL}/api/v1/transfer/finalize", json={"transfer_id": transfer_id})
    if res.status_code != 200:
        print(f"❌ Error en transfer/finalize: {res.text}")
        return

    fin_data = res.json()
    print("--------------------------------------------------")
    print(f"Estado en la Mac: {fin_data['status']}")
    print(f"Integridad SHA-256 válida: {fin_data['integrity_valid']}")
    print(f"Archivo guardado en: {fin_data['file_path']}")
    print("--------------------------------------------------")
    print("✅ Prueba completada con éxito.")


if __name__ == "__main__":
    run_simulation()