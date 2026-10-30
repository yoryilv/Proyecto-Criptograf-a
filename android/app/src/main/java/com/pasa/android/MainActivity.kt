package com.pasa.android

import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.provider.OpenableColumns
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.File
import java.security.interfaces.ECPublicKey

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    PasaScreen()
                }
            }
        }
    }
}

@Composable
fun PasaScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val client = remember { PasaClient(context) }
    val nsdHelper = remember { NsdHelper(context) }
    val bleScanner = remember { BleScanner(context) }

    // Estados de radar y dispositivos
    val discoveredDevices = remember { mutableStateListOf<DiscoveredDevice>() }
    var isScanning by remember { mutableStateOf(false) }

    // Estado del dispositivo seleccionado/emparejado
    var selectedDevice by remember { mutableStateOf<DiscoveredDevice?>(null) }
    var macKey by remember { mutableStateOf<ECPublicKey?>(null) }
    var sasCode by remember { mutableStateOf<String?>(null) }
    var isPairing by remember { mutableStateOf(false) }

    // Estados de archivo y transferencia saliente
    var selectedFileUri by remember { mutableStateOf<Uri?>(null) }
    var selectedFileName by remember { mutableStateOf("") }
    var selectedFileSize by remember { mutableLongStateOf(0L) }
    var isSending by remember { mutableStateOf(false) }
    var progress by remember { mutableIntStateOf(0) }
    var statusText by remember { mutableStateOf("Elige un método para buscar tu Mac") }

    // Estados de transferencia entrante (Mac -> Android)
    var incomingOffer by remember { mutableStateOf<PasaClient.OutboundOffer?>(null) }
    var wsConnection by remember { mutableStateOf<okhttp3.WebSocket?>(null) }

    fun startListeningToMac(deviceAddress: String) {
        wsConnection?.close(1000, "Reconectar")
        wsConnection = client.listenForOffers("http://$deviceAddress") { offer ->
            incomingOffer = offer
        }
    }

    // Gestor de permisos para escaneo Bluetooth Low Energy
    val blePermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestMultiplePermissions()
    ) { perms ->
        if (perms.values.all { it }) {
            isScanning = true
            statusText = "Buscando baliza BLE de la Mac..."
            bleScanner.startBleScan { device ->
                if (discoveredDevices.none { it.address == device.address }) {
                    discoveredDevices.add(device)
                }
            }
        } else {
            Toast.makeText(context, "Se necesitan permisos de Bluetooth para escanear", Toast.LENGTH_SHORT).show()
        }
    }

    val filePicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let {
            selectedFileUri = it
            context.contentResolver.query(it, null, null, null, null)?.use { cursor ->
                val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                if (cursor.moveToFirst()) {
                    selectedFileName = cursor.getString(nameIndex)
                    selectedFileSize = cursor.getLong(sizeIndex)
                }
            }
        }
    }

    DisposableEffect(Unit) {
        onDispose {
            nsdHelper.stopDiscovery()
            bleScanner.stopBleScan()
            wsConnection?.close(1000, "Salida")
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(20.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("Pasa — Descubrimiento Local", fontSize = 22.sp)
        Spacer(modifier = Modifier.height(14.dp))

        // Doble opción de escaneo: Wi-Fi (mDNS) o Bluetooth (BLE)
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Button(
                onClick = {
                    discoveredDevices.clear()
                    bleScanner.stopBleScan()
                    isScanning = true
                    statusText = "Escaneando red local vía Wi-Fi (mDNS)..."
                    nsdHelper.startDiscovery { device ->
                        if (discoveredDevices.none { it.address == device.address }) {
                            discoveredDevices.add(device)
                        }
                    }
                },
                modifier = Modifier.weight(1f),
                enabled = !isSending
            ) {
                Text("Wi-Fi (mDNS)", fontSize = 13.sp)
            }

            Button(
                onClick = {
                    discoveredDevices.clear()
                    nsdHelper.stopDiscovery()
                    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
                        blePermissionLauncher.launch(
                            arrayOf(
                                android.Manifest.permission.BLUETOOTH_SCAN,
                                android.Manifest.permission.BLUETOOTH_CONNECT
                            )
                        )
                    } else {
                        blePermissionLauncher.launch(
                            arrayOf(android.Manifest.permission.ACCESS_FINE_LOCATION)
                        )
                    }
                },
                modifier = Modifier.weight(1f),
                enabled = !isSending
            ) {
                Text("Bluetooth (BLE)", fontSize = 13.sp)
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        if (discoveredDevices.isNotEmpty()) {
            Text("Equipos detectados:", fontSize = 14.sp)
            Spacer(modifier = Modifier.height(6.dp))

            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f, fill = false)
            ) {
                items(discoveredDevices) { device ->
                    val isCurrent = selectedDevice?.address == device.address
                    val isAlreadyPaired = isCurrent && macKey != null

                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = if (isCurrent) MaterialTheme.colorScheme.primaryContainer
                            else MaterialTheme.colorScheme.surfaceVariant
                        ),
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp)
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(12.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(device.name, fontSize = 16.sp)
                                Text(device.address, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }

                            Button(
                                onClick = {
                                    selectedDevice = device
                                    scope.launch {
                                        try {
                                            isPairing = true
                                            statusText = "Comprueba el código SAS en ambas pantallas..."

                                            val (sas, key) = client.pairWithMac("http://${device.address}") { code ->
                                                sasCode = code
                                            }

                                            macKey = key
                                            startListeningToMac(device.address)
                                            statusText = "¡Emparejado con éxito! Listo para enviar y recibir."
                                            Toast.makeText(context, "Dispositivo Vinculado", Toast.LENGTH_SHORT).show()
                                        } catch (e: Exception) {
                                            statusText = "Error al emparejar: ${e.message}"
                                            Toast.makeText(context, "Fallo: ${e.message}", Toast.LENGTH_LONG).show()
                                        } finally {
                                            isPairing = false
                                        }
                                    }
                                },
                                enabled = !isPairing && !isSending && !isAlreadyPaired
                            ) {
                                Text(if (isAlreadyPaired) "Vinculado ✓" else "Emparejar")
                            }
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        sasCode?.let {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(12.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text("Código SAS (Comprobar en pantalla):", fontSize = 13.sp)
                    Text(it, fontSize = 28.sp, style = MaterialTheme.typography.headlineMedium)
                }
            }
            Spacer(modifier = Modifier.height(12.dp))
        }

        Button(
            onClick = { filePicker.launch("*/*") },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isSending && macKey != null
        ) {
            Text(if (selectedFileUri == null) "Seleccionar Archivo" else "Archivo: $selectedFileName")
        }

        Spacer(modifier = Modifier.height(8.dp))

        Button(
            onClick = {
                val target = selectedDevice ?: return@Button
                val targetKey = macKey ?: return@Button
                val uri = selectedFileUri ?: return@Button

                scope.launch {
                    try {
                        isSending = true
                        progress = 0
                        statusText = "Esperando que la Mac acepte el archivo..."

                        client.sendFile(
                            serverBaseUrl = "http://${target.address}",
                            macIdentityKey = targetKey,
                            fileUri = uri,
                            fileName = selectedFileName,
                            fileSize = selectedFileSize
                        ) { pct ->
                            statusText = "Cifrando y transmitiendo archivo..."
                            progress = pct
                        }

                        statusText = "¡Transferencia completada y verificada!"
                        Toast.makeText(context, "Archivo recibido por la Mac", Toast.LENGTH_LONG).show()
                    } catch (e: Exception) {
                        statusText = "Fallo: ${e.message}"
                        Toast.makeText(context, "Transferencia cancelada o fallida: ${e.message}", Toast.LENGTH_LONG).show()
                    } finally {
                        isSending = false
                    }
                }
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isSending && macKey != null && selectedFileUri != null
        ) {
            Text("Enviar a ${selectedDevice?.name ?: "la Mac"}")
        }

        if (isSending) {
            Spacer(modifier = Modifier.height(12.dp))
            LinearProgressIndicator(
                progress = { progress / 100f },
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text("$progress%")
        }

        Spacer(modifier = Modifier.height(8.dp))
        Text(statusText, fontSize = 13.sp, color = MaterialTheme.colorScheme.primary)
    }

    // Modal para recibir ofertas entrantes de la Mac
    incomingOffer?.let { offer ->
        AlertDialog(
            onDismissRequest = { incomingOffer = null },
            title = { Text("Archivo Entrante de la Mac") },
            text = {
                Text("¿Deseas recibir '${offer.fileName}' (${offer.fileSize / 1024} KB)?")
            },
            confirmButton = {
                Button(
                    onClick = {
                        val currentTargetKey = macKey ?: return@Button
                        val target = selectedDevice ?: return@Button
                        val offerToDownload = offer
                        incomingOffer = null

                        scope.launch {
                            try {
                                statusText = "Descargando y descifrando ${offerToDownload.fileName}..."
                                val destFolder = context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS)
                                val destFile = File(destFolder, offerToDownload.fileName)

                                client.acceptAndDownloadFile(
                                    serverBaseUrl = "http://${target.address}",
                                    macIdentityKey = currentTargetKey,
                                    offer = offerToDownload,
                                    destinationFile = destFile
                                ) { pct -> progress = pct }

                                statusText = "¡Archivo recibido e íntegro guardado!"
                                Toast.makeText(context, "Guardado en Descargas: ${destFile.name}", Toast.LENGTH_LONG).show()
                            } catch (e: Exception) {
                                statusText = "Fallo al recibir: ${e.message}"
                                Toast.makeText(context, "Error: ${e.message}", Toast.LENGTH_LONG).show()
                            }
                        }
                    }
                ) {
                    Text("Aceptar y Guardar")
                }
            },
            dismissButton = {
                OutlinedButton(
                    onClick = {
                        val offerToReject = incomingOffer
                        incomingOffer = null
                        val target = selectedDevice

                        if (offerToReject != null && target != null) {
                            scope.launch(Dispatchers.IO) {
                                try {
                                    val abortJson = JSONObject().apply {
                                        put("transfer_id", offerToReject.transferId)
                                        put("reason", "rejected_by_receiver")
                                    }
                                    val req = Request.Builder()
                                        .url("http://${target.address}/api/v1/transfer/abort")
                                        .post(abortJson.toString().toRequestBody("application/json".toMediaType()))
                                        .build()
                                    OkHttpClient().newCall(req).execute()
                                } catch (_: Exception) {}
                            }
                        }
                    }
                ) {
                    Text("Rechazar")
                }
            }
        )
    }
}