import base64
import hashlib
import os
from pathlib import Path
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


def load_or_generate_identity_key(key_path: Path) -> ec.EllipticCurvePrivateKey:
    """Carga la clave privada ECDSA P-256 de disco o genera una nueva en formato PKCS8 PEM."""
    if key_path.exists():
        pem_data = key_path.read_bytes()
        return serialization.load_pem_private_key(pem_data, password=None)

    key_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = ec.generate_private_key(ec.SECP256R1())

    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    key_path.write_bytes(pem_data)
    os.chmod(key_path, 0o600)

    return private_key


def public_key_to_uncompressed_bytes(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Serializa la clave pública a 65 bytes no comprimidos (0x04 || X || Y) según ANSI X9.62."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )


def uncompressed_bytes_to_public_key(pub_bytes: bytes) -> ec.EllipticCurvePublicKey:
    """Reconstruye una clave pública P-256 a partir de los 65 bytes no comprimidos."""
    if len(pub_bytes) != 65 or pub_bytes[0] != 0x04:
        raise ValueError("Formato de clave pública inválido: debe tener 65 bytes e iniciar con 0x04.")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes)


def public_key_to_base64(public_key: ec.EllipticCurvePublicKey) -> str:
    """Exporta la clave pública a Base64 para transportarla en payloads JSON."""
    return base64.b64encode(public_key_to_uncompressed_bytes(public_key)).decode("utf-8")


def base64_to_public_key(b64_str: str) -> ec.EllipticCurvePublicKey:
    """Importa una clave pública desde un string Base64 recibido por JSON."""
    raw_bytes = base64.b64decode(b64_str)
    return uncompressed_bytes_to_public_key(raw_bytes)


def sign_data(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> Tuple[int, int]:
    """Firma bytes arbitrarios con ECDSA SHA-256 y extrae los enteros (r, s)."""
    der_signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der_signature)
    return r, s


def verify_signature(
    public_key: ec.EllipticCurvePublicKey, data: bytes, r: int, s: int) -> bool:
    """Reensambla la firma DER a partir de (r, s) y valida su autenticidad matemática."""
    try:
        der_signature = utils.encode_dss_signature(r, s)
        public_key.verify(der_signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def rs_to_hex(r: int, s: int) -> Tuple[str, str]:
    """Convierte (r, s) a cadenas hexadecimales fijas de 64 caracteres (32 bytes)."""
    return f"{r:064x}", f"{s:064x}"


def hex_to_rs(r_hex: str, s_hex: str) -> Tuple[int, int]:
    """Convierte cadenas hexadecimales de 64 caracteres de vuelta a enteros (r, s)."""
    return int(r_hex, 16), int(s_hex, 16)


def compute_sas(pub_key_a_bytes: bytes, pub_key_b_bytes: bytes) -> str:
    """
    Calcula el SAS de 6 dígitos.
    Ordena las claves para garantizar simetría en ambos extremos.
    """
    ordered_keys = sorted([pub_key_a_bytes, pub_key_b_bytes])
    combined = ordered_keys[0] + ordered_keys[1]
    digest = hashlib.sha256(combined).digest()
    
    code_int = int.from_bytes(digest[:4], byteorder="big") % 1_000_000
    return f"{code_int:06d}"