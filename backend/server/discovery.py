import socket
from zeroconf import ServiceInfo
from zeroconf.asyncio import AsyncZeroconf

def get_local_ip() -> str:
    """Obtiene la IP local real de la Mac en la red Wi-Fi."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

class PasaDiscovery:
    def __init__(self):
        self.aio_zc = None
        self.info = None

    async def start(self, port: int = 8000):
        ip = get_local_ip()
        ip_bytes = socket.inet_aton(ip)

        self.aio_zc = AsyncZeroconf()
        self.info = ServiceInfo(
            type_="_pasa._tcp.local.",
            name="MacBook-Pro-de-Matias._pasa._tcp.local.",
            addresses=[ip_bytes],
            port=port,
            properties={"device_id": "MacBook-Pro-de-Matias", "version": "1.0"},
            server="pasamac.local."
        )
        await self.aio_zc.async_register_service(self.info)
        print(f"📡 Broadcast ZeroConf activado. Android puede encontrarte en {ip}:{port}")

    async def stop(self):
        if self.aio_zc and self.info:
            await self.aio_zc.async_unregister_service(self.info)
            await self.aio_zc.async_close()
        print("📡 Broadcast ZeroConf apagado.")