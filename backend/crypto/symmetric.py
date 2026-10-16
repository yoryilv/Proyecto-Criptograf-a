"""
lfss.py — Local File Share Stream: chunked AES-256-GCM with a hybrid nonce.
"""

from __future__ import annotations

import os
import struct
from typing import BinaryIO, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CHUNK_SIZE = 64 * 1024  # plaintext bytes per chunk
NONCE_LEN = 12  # 96-bit nonce (NIST recommended)
TAG_LEN = 16  # AESGCM uses full 128-bit tags
KEY_LEN = 32  # AES-256

MAGIC = b"LFSS"
VERSION = 1
HEADER = struct.Struct(">4sB12s")
HEADER_LEN = HEADER.size  # 17


# ----------------------------------------------------------- key / nonce / aad


def derive_file_key(master_key: bytes, base_nonce: bytes) -> bytes:
    """One fresh AES-256 key per file, bound to that file's random base nonce."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=base_nonce,
        info=b"lfss/file-key/v1",
    ).derive(master_key)


def chunk_nonce(base_nonce: bytes, counter: int) -> bytes:
    """nonce_i = base_nonce XOR i  (i as a big-endian integer, same width)."""
    return (int.from_bytes(base_nonce, "big") ^ counter).to_bytes(NONCE_LEN, "big")


def chunk_aad(header: bytes, index: int) -> bytes:
    """Bind each chunk to the file header and to its position."""
    return header + struct.pack(">Q", index)


# ---------------------------------------------------------------- helpers


def _read_exact(stream: BinaryIO, n: int) -> bytes:
    """Read up to n bytes, tolerating short reads (sockets / HTTP bodies)."""
    out = bytearray()
    while len(out) < n:
        block = stream.read(n - len(out))
        if not block:
            break
        out += block
    return bytes(out)


def _chunkify(stream: BinaryIO, chunk_size: int) -> Iterator[tuple[int, bytes]]:
    """Yield (index, plaintext_chunk).

    Guarantees every non-final chunk is exactly `chunk_size` and the final
    chunk is strictly shorter (an empty one is appended when the input length
    is an exact multiple of `chunk_size`). This makes the short final chunk an
    unambiguous end-of-stream marker.
    """
    index = 0
    buf = _read_exact(stream, chunk_size)
    while len(buf) == chunk_size:
        nxt = _read_exact(stream, chunk_size)
        if not nxt:  # `buf` was the last data
            yield index, buf
            yield index + 1, b""
            return
        yield index, buf
        index += 1
        buf = nxt
    yield index, buf  # short (possibly empty) final chunk


# ---------------------------------------------------------------- encrypt


def iter_encrypt(
    src: BinaryIO, master_key: bytes, chunk_size: int = CHUNK_SIZE
) -> Iterator[bytes]:
    """Yield the encrypted byte stream: header first, then one AEAD chunk at a time.

    Nothing larger than one chunk is ever held in memory.
    """
    base_nonce = os.urandom(NONCE_LEN)
    header = HEADER.pack(MAGIC, VERSION, base_nonce)
    ae = AESGCM(derive_file_key(master_key, base_nonce))
    yield header
    for index, plaintext in _chunkify(src, chunk_size):
        yield ae.encrypt(
            chunk_nonce(base_nonce, index), plaintext, chunk_aad(header, index)
        )


def encrypt_stream(
    src: BinaryIO, dst: BinaryIO, master_key: bytes, chunk_size: int = CHUNK_SIZE
) -> None:
    for block in iter_encrypt(src, master_key, chunk_size):
        dst.write(block)


# ---------------------------------------------------------------- decrypt


def decrypt_stream(
    src: BinaryIO, dst: BinaryIO, master_key: bytes, chunk_size: int = CHUNK_SIZE
) -> None:
    header = _read_exact(src, HEADER_LEN)
    if len(header) != HEADER_LEN:
        raise ValueError("truncated header")
    magic, version, base_nonce = HEADER.unpack(header)
    if magic != MAGIC:
        raise ValueError("not an LFSS stream")
    if version != VERSION:
        raise ValueError(f"unsupported version {version}")

    ae = AESGCM(derive_file_key(master_key, base_nonce))
    index = 0
    while True:
        ct = _read_exact(src, chunk_size + TAG_LEN)
        if len(ct) < TAG_LEN:
            # A full-size final chunk is illegal, so truncation lands here.
            raise ValueError("truncated stream: missing final chunk")

        is_final = len(ct) < chunk_size + TAG_LEN
        try:
            plaintext = ae.decrypt(
                chunk_nonce(base_nonce, index), ct, chunk_aad(header, index)
            )
        except InvalidTag as exc:
            raise ValueError(f"authentication failed at chunk {index}") from exc
        dst.write(plaintext)

        index += 1
        if is_final:
            break

    if _read_exact(src, 1):
        raise ValueError("trailing data after final chunk")

if __name__ == "__main__":
    # Solo se ejecuta si se corre el script directamente, nunca al correr el server
    import io
    dummy_data = b"Prueba de flujo seguro Pasa"
    master = AESGCM.generate_key(bit_length=256)
    
    enc_out = io.BytesIO()
    encrypt_stream(io.BytesIO(dummy_data), enc_out, master)
    
    dec_out = io.BytesIO()
    decrypt_stream(io.BytesIO(enc_out.getvalue()), dec_out, master)
    assert dec_out.getvalue() == dummy_data
    print("Prueba LFSS completada con éxito.")