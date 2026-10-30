import sys
import objc
import threading
import CoreBluetooth
from Foundation import (
    NSDictionary,
    NSObject,
    NSString,
    NSData,
    CBUUID,
)

PASA_UUID = "0000fe50-0000-1000-8000-00805f9b34fb"


class BleAdvertiser(NSObject):
    def init(self):
        self = objc.super(BleAdvertiser, self).init()
        if self is None:
            return None
        self.manager = None
        self.ip_payload = None
        self.device_name = "MacBook-Pro-de-Matias"
        return self

    def start_advertising(self, ip_address: str, port: int):
        self.ip_payload = f"{ip_address}:{port}".encode("utf-8")
        # Iniciar CBPeripheralManager nativo
        self.manager = CoreBluetooth.CBPeripheralManager.alloc().initWithDelegate_queue_(self, None)

    def peripheralManagerDidUpdateState_(self, peripheral):
        if peripheral.state() == CoreBluetooth.CBManagerStatePoweredOn:
            service_uuid = CBUUID.UUIDWithString_(PASA_UUID)
            service_data = NSData.dataWithBytes_length_(self.ip_payload, len(self.ip_payload))

            ad_data = {
                CoreBluetooth.CBAdvertisementDataLocalNameKey: self.device_name,
                CoreBluetooth.CBAdvertisementDataServiceUUIDsKey: [service_uuid],
                CoreBluetooth.CBAdvertisementDataServiceDataKey: {service_uuid: service_data},
            }

            self.manager.startAdvertising_(ad_data)
            print(f"📡 Baliza BLE de Pasa activa anunciando {self.device_name} ({self.ip_payload.decode('utf-8')})")
        else:
            print(f"⚠️ Estado Bluetooth de macOS: {peripheral.state()}")


def start_ble_beacon_in_background(ip_address: str, port: int = 8000):
    """Inicia el anuncio BLE en un hilo secundario con NSRunLoop."""
    import AppKit

    def runner():
        advertiser = BleAdvertiser.alloc().init()
        advertiser.start_advertising(ip_address, port)
        AppKit.NSRunLoop.currentRunLoop().run()

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()