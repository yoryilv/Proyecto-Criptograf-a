package com.pasa.android

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import android.util.Log

data class DiscoveredDevice(
    val name: String,
    val host: String,
    val port: Int
) {
    val address: String get() = "$host:$port"
}

class NsdHelper(private val context: Context) {

    private val nsdManager = context.getSystemService(Context.NSD_SERVICE) as NsdManager
    private val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
    private var multicastLock: WifiManager.MulticastLock? = null

    private val serviceType = "_pasa._tcp."
    private var discoveryListener: NsdManager.DiscoveryListener? = null

    fun startDiscovery(onDeviceFound: (DiscoveredDevice) -> Unit) {
        stopDiscovery()

        // Adquirir bloqueo de multidifusión (necesario en celulares físicos para recibir mDNS)
        try {
            multicastLock = wifiManager.createMulticastLock("pasa_multicast_lock").apply {
                setReferenceCounted(true)
                acquire()
            }
        } catch (e: Exception) {
            Log.e("NsdHelper", "Error adquiriendo MulticastLock: ${e.message}")
        }

        discoveryListener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(regType: String) {
                Log.d("NsdHelper", "Búsqueda mDNS iniciada: $regType")
            }

            override fun onServiceFound(service: NsdServiceInfo) {
                if (service.serviceType.contains("pasa")) {
                    resolveService(service, onDeviceFound)
                }
            }

            override fun onServiceLost(service: NsdServiceInfo) {
                Log.d("NsdHelper", "Servicio fuera de alcance: ${service.serviceName}")
            }

            override fun onDiscoveryStopped(serviceType: String) {}
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) { stopDiscovery() }
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) { stopDiscovery() }
        }

        nsdManager.discoverServices(serviceType, NsdManager.PROTOCOL_DNS_SD, discoveryListener)
    }

    private fun resolveService(serviceInfo: NsdServiceInfo, onDeviceFound: (DiscoveredDevice) -> Unit) {
        nsdManager.resolveService(serviceInfo, object : NsdManager.ResolveListener {
            override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
                Log.e("NsdHelper", "Fallo al resolver servicio: $errorCode")
            }

            override fun onServiceResolved(resolvedInfo: NsdServiceInfo) {
                val host = resolvedInfo.host.hostAddress ?: return
                // Filtrar direcciones IPv6 directas si se prefiere IPv4
                val cleanHost = if (host.contains("%")) host.substringBefore("%") else host
                val device = DiscoveredDevice(
                    name = resolvedInfo.serviceName.replace("\\032", " "),
                    host = cleanHost,
                    port = resolvedInfo.port
                )
                onDeviceFound(device)
            }
        })
    }

    fun stopDiscovery() {
        discoveryListener?.let {
            try {
                nsdManager.stopServiceDiscovery(it)
            } catch (_: Exception) {}
            discoveryListener = null
        }
        if (multicastLock?.isHeld == true) {
            multicastLock?.release()
            multicastLock = null
        }
    }
}