import hashlib
from pathlib import Path


def compute_file_sha256(file_path: Path, chunk_size: int = 1024 * 1024) -> str:
    """
    Lee un archivo físico en fragmentos (por defecto 1 MiB) y calcula su hash SHA-256.
    Retorna el hash en formato hexadecimal (64 caracteres).
    """
    if not file_path.exists():
        raise FileNotFoundError(f"El archivo temporal no existe: {file_path}")

    sha256_hash = hashlib.sha256()

    # Abrimos el archivo en modo binario
    with open(file_path, "rb") as f:
        # iter() lee el archivo en bloques de 'chunk_size' hasta que f.read devuelve b"" (vacío)
        for byte_block in iter(lambda: f.read(chunk_size), b""):
            sha256_hash.update(byte_block)

    return sha256_hash.hexdigest()


def verify_file_integrity(file_path: Path, expected_hash_hex: str) -> bool:
    """
    Compara el hash calculado del archivo en disco con el hash que mandó el emisor en el JSON.
    Retorna True si el archivo es idéntico al original.
    """
    actual_hash = compute_file_sha256(file_path)
    return actual_hash.lower() == expected_hash_hex.lower()