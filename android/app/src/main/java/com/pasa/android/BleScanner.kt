package com.pasa.android

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.ParcelUuid
import android.util.Log
import java.nio.charset.StandardCharsets
import java.util.UUID

class BleScanner(private val context: Context) {

    companion object {
        // UUID de 128 bits exclusivo de Pasa
        val PASA_SERVICE_UUID: UUID = UUID.fromString("0000fe50-0000-1000-8000-00805f9b34fb")
    }

    private val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val adapter: BluetoothAdapter? = bluetoothManager.adapter
    private val scanner get() = adapter?.bluetoothLeScanner
    private var scanCallback: ScanCallback? = null

    val isBluetoothEnabled: Boolean
        get() = adapter?.isEnabled == true

    @SuppressLint("MissingPermission")
    fun startBleScan(onDeviceFound: (DiscoveredDevice) -> Unit) {
        stopBleScan()
        if (!isBluetoothEnabled) {
            Log.e("BleScanner", "Bluetooth apagado")
            return
        }

        val parcelUuid = ParcelUuid(PASA_SERVICE_UUID)
        val filter = ScanFilter.Builder()
            .setServiceUuid(parcelUuid)
            .build()

        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()

        scanCallback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                val record = result.scanRecord ?: return
                val serviceData = record.getServiceData(parcelUuid)

                var host = ""
                var port = 8000

                // Si la Mac envió IP y puerto en el payload del anuncio
                if (serviceData != null && serviceData.isNotEmpty()) {
                    val payload = String(serviceData, StandardCharsets.UTF_8)
                    val parts = payload.split(":")
                    if (parts.isNotEmpty()) host = parts[0]
                    if (parts.size > 1) port = parts[1].toIntOrNull() ?: 8000
                }

                val deviceName = record.deviceName ?: result.device.name ?: "MacBook (BLE)"
                if (host.isNotEmpty()) {
                    onDeviceFound(DiscoveredDevice(name = deviceName, host = host, port = port))
                }
            }

            override fun onScanFailed(errorCode: Int) {
                Log.e("BleScanner", "Fallo al escanear BLE: $errorCode")
            }
        }

        scanner?.startScan(listOf(filter), settings, scanCallback)
    }

    @SuppressLint("MissingPermission")
    fun stopBleScan() {
        scanCallback?.let {
            try {
                scanner?.stopScan(it)
            } catch (_: Exception) {}
            scanCallback = null
        }
    }
}