from typing import Any, Dict

# Dispositivos de confianza: device_id -> public_key_bytes (65 bytes)
trusted_devices: Dict[str, bytes] = {}

# Solicitudes de pairing pendientes de aprobación: device_id -> dict
pending_pairings: Dict[str, Dict[str, Any]] = {}

# Transferencias activas: transfer_id -> dict
active_transfers: Dict[str, Dict[str, Any]] = {}