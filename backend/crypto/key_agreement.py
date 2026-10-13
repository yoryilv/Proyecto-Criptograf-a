from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto.identity import (
    public_key_to_uncompressed_bytes,
    sign_data,
    verify_signature,
)

# Contexto fijo para la derivación con HKDF
HKDF_INFO = b"pasa-session-v1"


def generate_ephemeral_keypair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Genera un par de claves efimeras ECDHE (P-256) unico para una sesion."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def sign_ephemeral_public_key(
    identity_private_key: ec.EllipticCurvePrivateKey,
    ephemeral_public_key: ec.EllipticCurvePublicKey,
) -> Tuple[int, int]:
    """
    Autentica la clave efimera firmando sus 65 bytes con la identidad permanente.
    Devuelve la tupla (r, s) para evitar ataques Man-in-the-Middle (MITM).
    """
    eph_bytes = public_key_to_uncompressed_bytes(ephemeral_public_key)
    return sign_data(identity_private_key, eph_bytes)


def verify_ephemeral_public_key(
    peer_identity_public_key: ec.EllipticCurvePublicKey,
    peer_ephemeral_public_key_bytes: bytes,
    r: int, s: int,
) -> bool:
    """Verifica que la clave efimera recibida provenga realmente del dispositivo vinculado."""
    return verify_signature(
        public_key=peer_identity_public_key,
        data=peer_ephemeral_public_key_bytes,
        r=r,
        s=s,
    )


def compute_shared_secret(
    my_ephemeral_private_key: ec.EllipticCurvePrivateKey,
    peer_ephemeral_public_key: ec.EllipticCurvePublicKey,
) -> bytes:
    """Calcula el secreto compartido Z = ECDH(priv_local, pub_remota)."""
    return my_ephemeral_private_key.exchange(ec.ECDH(), peer_ephemeral_public_key)


def derive_session_key(
    shared_secret: bytes,
    my_eph_pub_bytes: bytes,
    peer_eph_pub_bytes: bytes,
) -> bytes:
    """
    Transforma el secreto compartido en una clave simetrica de 256 bits (K_AES) usando HKDF-SHA256.
    Ordena las claves efimeras lexicograficamente para que el salt sea identico en Mac y Android.
    """
    ordered_eph_keys = sorted([my_eph_pub_bytes, peer_eph_pub_bytes])
    salt = ordered_eph_keys[0] + ordered_eph_keys[1]

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits para AES-256
        salt=salt,
        info=HKDF_INFO,
    )
    return hkdf.derive(shared_secret)