package com.pasa.android

import android.content.Context
import android.net.Uri
import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.spec.*
import java.util.Locale
import java.util.UUID
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.ceil

class PasaClient(private val context: Context) {

    data class OutboundOffer(
        val transferId: String,
        val fileName: String,
        val fileSize: Long,
        val sha256Expected: String,
        val macEphPubBytes: ByteArray,
        val sigR: String,
        val sigS: String
    )

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .writeTimeout(60, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .build()

    // Identidad permanente P-256
    val identityKeyPair: KeyPair by lazy { generateP256KeyPair() }
    val deviceId = "Android-Device"

    companion object {
        private const val HTTP_CHUNK_SIZE = 256 * 1024 // 256 KiB para transporte HTTP
        private const val LFSS_CHUNK_SIZE = 64 * 1024  // 64 KiB tamaño de bloque LFSS
        private const val LFSS_TAG_LEN = 16
        private const val LFSS_HEADER_LEN = 17
    }

    // --- Criptografía Básica ---

    private fun generateP256KeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        return kpg.generateKeyPair()
    }

    fun getPublicKeyUncompressedBytes(publicKey: ECPublicKey): ByteArray {
        val x = publicKey.w.affineX.toByteArray().stripLeadingZeros(32)
        val y = publicKey.w.affineY.toByteArray().stripLeadingZeros(32)
        val out = ByteArray(65)
        out[0] = 0x04
        System.arraycopy(x, 0, out, 1, 32)
        System.arraycopy(y, 0, out, 33, 32)
        return out
    }

    fun parseUncompressedPublicKey(bytes: ByteArray): ECPublicKey {
        require(bytes.size == 65 && bytes[0] == 0x04.toByte()) { "Formato de clave pública inválido" }
        val x = BigInteger(1, bytes.copyOfRange(1, 33))
        val y = BigInteger(1, bytes.copyOfRange(33, 65))
        val kf = KeyFactory.getInstance("EC")
        val params = (generateP256KeyPair().public as ECPublicKey).params
        return kf.generatePublic(ECPublicKeySpec(ECPoint(x, y), params)) as ECPublicKey
    }

    private fun ByteArray.stripLeadingZeros(length: Int): ByteArray {
        val result = ByteArray(length)
        val srcPos = if (this.size > length) this.size - length else 0
        val destPos = if (length > this.size) length - this.size else 0
        val copyLen = minOf(this.size - srcPos, length)
        System.arraycopy(this, srcPos, result, destPos, copyLen)
        return result
    }

    fun computeSas(keyA: ByteArray, keyB: ByteArray): String {
        val (first, second) = if (compareByteArrays(keyA, keyB) <= 0) Pair(keyA, keyB) else Pair(keyB, keyA)
        val md = MessageDigest.getInstance("SHA-256")
        md.update(first)
        md.update(second)
        val digest = md.digest()
        val num = ByteBuffer.wrap(digest, 0, 4).int.toLong() and 0xFFFFFFFFL
        return String.format(Locale.US, "%06d", num % 1000000)
    }

    private fun compareByteArrays(a: ByteArray, b: ByteArray): Int {
        val minLen = minOf(a.size, b.size)
        for (i in 0 until minLen) {
            val cmp = (a[i].toInt() and 0xFF).compareTo(b[i].toInt() and 0xFF)
            if (cmp != 0) return cmp
        }
        return a.size.compareTo(b.size)
    }

    // --- Emparejamiento ---

    suspend fun pairWithMac(
        serverBaseUrl: String,
        onSasReady: (String) -> Unit = {}
    ): Pair<String, ECPublicKey> = withContext(Dispatchers.IO) {
        val myPubBytes = getPublicKeyUncompressedBytes(identityKeyPair.public as ECPublicKey)
        val myPubB64 = Base64.encodeToString(myPubBytes, Base64.NO_WRAP)

        // 1. /pair/init
        val initJson = JSONObject().apply {
            put("device_id", deviceId)
            put("identity_public_key", myPubB64)
            put("timestamp", System.currentTimeMillis() / 1000)
        }

        val initReq = Request.Builder()
            .url("$serverBaseUrl/api/v1/pair/init")
            .post(initJson.toString().toRequestBody("application/json".toMediaType()))
            .build()

        val initRes = httpClient.newCall(initReq).execute()
        val initData = JSONObject(initRes.body?.string() ?: throw Exception("Respuesta vacía"))
        val macPubB64 = initData.getString("identity_public_key")
        val macPubBytes = Base64.decode(macPubB64, Base64.NO_WRAP)
        val macPublicKey = parseUncompressedPublicKey(macPubBytes)

        val sasCode = computeSas(myPubBytes, macPubBytes)
        withContext(Dispatchers.Main) {
            onSasReady(sasCode)
        }

        // 2. /pair/confirm (espera en el backend hasta confirmación en web)
        val confirmJson = JSONObject().apply {
            put("device_id", deviceId)
            put("confirmed", true)
        }
        val confirmReq = Request.Builder()
            .url("$serverBaseUrl/api/v1/pair/confirm")
            .post(confirmJson.toString().toRequestBody("application/json".toMediaType()))
            .build()

        val confirmRes = httpClient.newCall(confirmReq).execute()
        if (!confirmRes.isSuccessful) {
            throw Exception("Emparejamiento rechazado o expirado")
        }

        Pair(sasCode, macPublicKey)
    }

    // --- Envío: Android -> Mac ---

    suspend fun sendFile(
        serverBaseUrl: String,
        macIdentityKey: ECPublicKey,
        fileUri: Uri,
        fileName: String,
        fileSize: Long,
        onProgress: (Int) -> Unit
    ) = withContext(Dispatchers.IO) {
        val transferId = UUID.randomUUID().toString()

        val fileSha256 = computeFileSha256(fileUri)

        val totalLfssChunks = (fileSize / LFSS_CHUNK_SIZE) + 1
        val exactEncryptedSize = fileSize + LFSS_HEADER_LEN + (totalLfssChunks * LFSS_TAG_LEN)
        val totalHttpChunks = maxOf(1, ceil(exactEncryptedSize.toDouble() / HTTP_CHUNK_SIZE).toInt())

        val reqJson = JSONObject().apply {
            put("device_id", deviceId)
            put("transfer_id", transferId)
            put("file_name", fileName)
            put("file_size_bytes", fileSize)
            put("total_chunks", totalHttpChunks)
            put("sha256_expected", fileSha256)
        }

        val requestCall = Request.Builder()
            .url("$serverBaseUrl/api/v1/transfer/request")
            .post(reqJson.toString().toRequestBody("application/json".toMediaType()))
            .build()
        val reqRes = httpClient.newCall(requestCall).execute()
        if (!reqRes.isSuccessful) throw Exception("Error en transfer/request: ${reqRes.code}")

        val ephKeyPair = generateP256KeyPair()
        val ephPubBytes = getPublicKeyUncompressedBytes(ephKeyPair.public as ECPublicKey)
        val ephPubB64 = Base64.encodeToString(ephPubBytes, Base64.NO_WRAP)
        val (sigR, sigS) = signBytes(identityKeyPair.private, ephPubBytes)

        val hsJson = JSONObject().apply {
            put("device_id", deviceId)
            put("transfer_id", transferId)
            put("ephemeral_public_key", ephPubB64)
            put("signature_r", sigR)
            put("signature_s", sigS)
        }

        val hsReq = Request.Builder()
            .url("$serverBaseUrl/api/v1/transfer/handshake")
            .post(hsJson.toString().toRequestBody("application/json".toMediaType()))
            .build()

        val hsRes = httpClient.newCall(hsReq).execute()
        val hsData = JSONObject(hsRes.body?.string() ?: throw Exception("Fallo en handshake"))

        val macEphPubBytes = Base64.decode(hsData.getString("ephemeral_public_key"), Base64.NO_WRAP)
        val macEphPub = parseUncompressedPublicKey(macEphPubBytes)

        val validMacSig = verifySignature(
            macIdentityKey,
            macEphPubBytes,
            hsData.getString("signature_r"),
            hsData.getString("signature_s")
        )
        if (!validMacSig) throw SecurityException("Firma de la Mac inválida (Posible MITM)")

        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(ephKeyPair.private)
        ka.doPhase(macEphPub, true)
        val sharedSecret = ka.generateSecret()

        val (first, second) = if (compareByteArrays(ephPubBytes, macEphPubBytes) <= 0)
            Pair(ephPubBytes, macEphPubBytes) else Pair(macEphPubBytes, ephPubBytes)
        val salt = first + second

        val kSession = deriveHkdf(sharedSecret, salt, "pasa-session-v1".toByteArray(Charsets.US_ASCII))

        val encryptedData = encryptStreamLfss(fileUri, kSession)
        val actualChunks = maxOf(1, ceil(encryptedData.size.toDouble() / HTTP_CHUNK_SIZE).toInt())

        for (i in 0 until actualChunks) {
            val from = i * HTTP_CHUNK_SIZE
            val to = minOf(from + HTTP_CHUNK_SIZE, encryptedData.size)
            val chunk = encryptedData.copyOfRange(from, to)

            val chunkReq = Request.Builder()
                .url("$serverBaseUrl/api/v1/transfer/chunk")
                .header("Content-Type", "application/octet-stream")
                .header("X-Transfer-Id", transferId)
                .header("X-Chunk-Index", i.toString())
                .post(chunk.toRequestBody("application/octet-stream".toMediaType()))
                .build()

            val chunkRes = httpClient.newCall(chunkReq).execute()
            if (!chunkRes.isSuccessful) throw Exception("Fallo en chunk $i: ${chunkRes.code}")
            onProgress(((i + 1).toDouble() / actualChunks * 100).toInt())
        }

        val finJson = JSONObject().apply { put("transfer_id", transferId) }
        val finReq = Request.Builder()
            .url("$serverBaseUrl/api/v1/transfer/finalize")
            .post(finJson.toString().toRequestBody("application/json".toMediaType()))
            .build()

        val finRes = httpClient.newCall(finReq).execute()
        val finBody = finRes.body?.string() ?: "{}"
        val finData = JSONObject(finBody)
        if (!finRes.isSuccessful || !finData.optBoolean("integrity_valid", false)) {
            throw SecurityException("Error de integridad SHA-256 en la Mac: $finBody")
        }
    }

    // --- Recepción: Mac -> Android ---

    fun listenForOffers(
        serverBaseUrl: String,
        onOfferReceived: (OutboundOffer) -> Unit
    ): okhttp3.WebSocket {
        val wsUrl = serverBaseUrl.replace("http://", "ws://").replace("https://", "wss://") + "/ws"
        val req = Request.Builder().url(wsUrl).build()

        return httpClient.newWebSocket(req, object : okhttp3.WebSocketListener() {
            override fun onMessage(webSocket: okhttp3.WebSocket, text: String) {
                try {
                    val json = JSONObject(text)
                    if (json.optString("type") == "OUTBOUND_TRANSFER_OFFER" &&
                        json.optString("target_device_id") == deviceId
                    ) {
                        val offer = OutboundOffer(
                            transferId = json.getString("transfer_id"),
                            fileName = json.getString("file_name"),
                            fileSize = json.getLong("file_size"),
                            sha256Expected = json.getString("sha256_expected"),
                            macEphPubBytes = Base64.decode(json.getString("ephemeral_public_key"), Base64.NO_WRAP),
                            sigR = json.getString("signature_r"),
                            sigS = json.getString("signature_s")
                        )
                        onOfferReceived(offer)
                    }
                } catch (_: Exception) {}
            }
        })
    }

    suspend fun acceptAndDownloadFile(
        serverBaseUrl: String,
        macIdentityKey: ECPublicKey,
        offer: OutboundOffer,
        destinationFile: java.io.File,
        onProgress: (Int) -> Unit
    ) = withContext(Dispatchers.IO) {
        val validMacSig = verifySignature(macIdentityKey, offer.macEphPubBytes, offer.sigR, offer.sigS)
        if (!validMacSig) throw SecurityException("Firma de la Mac inválida (Posible MITM)")

        val macEphPub = parseUncompressedPublicKey(offer.macEphPubBytes)

        val ephKeyPair = generateP256KeyPair()
        val ephPubBytes = getPublicKeyUncompressedBytes(ephKeyPair.public as ECPublicKey)
        val ephPubB64 = Base64.encodeToString(ephPubBytes, Base64.NO_WRAP)
        val (sigR, sigS) = signBytes(identityKeyPair.private, ephPubBytes)

        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(ephKeyPair.private)
        ka.doPhase(macEphPub, true)
        val sharedSecret = ka.generateSecret()

        val (first, second) = if (compareByteArrays(ephPubBytes, offer.macEphPubBytes) <= 0)
            Pair(ephPubBytes, offer.macEphPubBytes) else Pair(offer.macEphPubBytes, ephPubBytes)
        val salt = first + second
        val kSession = deriveHkdf(sharedSecret, salt, "pasa-session-v1".toByteArray(Charsets.US_ASCII))

        val hsJson = JSONObject().apply {
            put("transfer_id", offer.transferId)
            put("device_id", deviceId)
            put("ephemeral_public_key", ephPubB64)
            put("signature_r", sigR)
            put("signature_s", sigS)
        }

        val hsReq = Request.Builder()
            .url("$serverBaseUrl/api/v1/transfer/outbound/handshake")
            .post(hsJson.toString().toRequestBody("application/json".toMediaType()))
            .build()

        val hsRes = httpClient.newCall(hsReq).execute()
        if (!hsRes.isSuccessful) throw Exception("Error en handshake de descarga")

        val streamReq = Request.Builder()
            .url("$serverBaseUrl/api/v1/transfer/outbound/stream/${offer.transferId}")
            .get()
            .build()

        val streamRes = httpClient.newCall(streamReq).execute()
        val body = streamRes.body ?: throw Exception("Cuerpo de descarga vacío")

        body.byteStream().use { input ->
            java.io.FileOutputStream(destinationFile).use { output ->
                decryptStreamLfss(input, output, kSession)
            }
        }

        val localSha = computeFileSha256(destinationFile)
        if (!localSha.equals(offer.sha256Expected, ignoreCase = true)) {
            destinationFile.delete()
            throw SecurityException("Error de integridad SHA-256 en Android")
        }

        val compReq = Request.Builder()
            .url("$serverBaseUrl/api/v1/transfer/outbound/complete")
            .header("transfer-id", offer.transferId)
            .post(ByteArray(0).toRequestBody(null))
            .build()
        httpClient.newCall(compReq).execute()
    }

    // --- Máquina de Estados LFSS (Cifrado y Descifrado) ---

    private fun encryptStreamLfss(uri: Uri, masterKey: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        val baseNonce = ByteArray(12).also { SecureRandom().nextBytes(it) }

        val header = ByteBuffer.allocate(LFSS_HEADER_LEN)
            .put("LFSS".toByteArray(Charsets.US_ASCII))
            .put(1.toByte())
            .put(baseNonce)
            .array()
        out.write(header)

        val fileKey = deriveHkdf(masterKey, baseNonce, "lfss/file-key/v1".toByteArray(Charsets.US_ASCII))
        val secretKey = SecretKeySpec(fileKey, "AES")

        val inputStream: InputStream = context.contentResolver.openInputStream(uri)
            ?: throw Exception("No se pudo leer el archivo")

        val buffer = ByteArray(LFSS_CHUNK_SIZE)
        var index = 0L
        var bufLen = readExact(inputStream, buffer)

        while (bufLen == LFSS_CHUNK_SIZE) {
            val nextBuffer = ByteArray(LFSS_CHUNK_SIZE)
            val nextLen = readExact(inputStream, nextBuffer)
            if (nextLen == 0) {
                encryptAndWriteLfssChunk(out, secretKey, baseNonce, header, index, buffer, bufLen)
                encryptAndWriteLfssChunk(out, secretKey, baseNonce, header, index + 1L, ByteArray(0), 0)
                inputStream.close()
                return out.toByteArray()
            }
            encryptAndWriteLfssChunk(out, secretKey, baseNonce, header, index, buffer, bufLen)
            index++
            System.arraycopy(nextBuffer, 0, buffer, 0, nextLen)
            bufLen = nextLen
        }

        encryptAndWriteLfssChunk(out, secretKey, baseNonce, header, index, buffer, bufLen)
        inputStream.close()
        return out.toByteArray()
    }

    private fun decryptStreamLfss(
        input: InputStream,
        output: java.io.OutputStream,
        masterKey: ByteArray
    ) {
        val header = ByteArray(LFSS_HEADER_LEN)
        val readHeader = readExact(input, header)
        if (readHeader != LFSS_HEADER_LEN) throw IllegalArgumentException("Encabezado LFSS truncado")

        val magic = String(header.copyOfRange(0, 4), Charsets.US_ASCII)
        if (magic != "LFSS") throw IllegalArgumentException("Formato no es LFSS")
        val baseNonce = header.copyOfRange(5, 17)

        val fileKey = deriveHkdf(masterKey, baseNonce, "lfss/file-key/v1".toByteArray(Charsets.US_ASCII))
        val secretKey = SecretKeySpec(fileKey, "AES")

        val buffer = ByteArray(LFSS_CHUNK_SIZE + LFSS_TAG_LEN)
        var index = 0L

        while (true) {
            val bytesRead = readExact(input, buffer)
            if (bytesRead < LFSS_TAG_LEN) throw IllegalArgumentException("Fragmento truncado")

            val isFinal = bytesRead < (LFSS_CHUNK_SIZE + LFSS_TAG_LEN)
            val nonce = chunkNonce(baseNonce, index)
            val aad = chunkAad(header, index)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, nonce))
            cipher.updateAAD(aad)

            val plaintext = cipher.doFinal(buffer, 0, bytesRead)
            output.write(plaintext)

            index++
            if (isFinal) break
        }
    }

    private fun encryptAndWriteLfssChunk(
        out: ByteArrayOutputStream,
        secretKey: SecretKeySpec,
        baseNonce: ByteArray,
        header: ByteArray,
        index: Long,
        data: ByteArray,
        length: Int
    ) {
        val nonce = chunkNonce(baseNonce, index)
        val aad = chunkAad(header, index)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)

        val ciphertext = cipher.doFinal(data, 0, length)
        out.write(ciphertext)
    }

    private fun chunkNonce(baseNonce: ByteArray, counter: Long): ByteArray {
        val baseInt = BigInteger(1, baseNonce)
        val xorInt = baseInt.xor(BigInteger.valueOf(counter))
        val bytes = xorInt.toByteArray()
        val result = ByteArray(12)
        if (bytes.size >= 12) {
            System.arraycopy(bytes, bytes.size - 12, result, 0, 12)
        } else {
            System.arraycopy(bytes, 0, result, 12 - bytes.size, bytes.size)
        }
        return result
    }

    private fun chunkAad(header: ByteArray, index: Long): ByteArray {
        return ByteBuffer.allocate(LFSS_HEADER_LEN + 8)
            .put(header)
            .putLong(index)
            .array()
    }

    private fun readExact(stream: InputStream, buffer: ByteArray): Int {
        var totalRead = 0
        while (totalRead < buffer.size) {
            val read = stream.read(buffer, totalRead, buffer.size - totalRead)
            if (read == -1) break
            totalRead += read
        }
        return totalRead
    }

    private fun deriveHkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray): ByteArray {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(ikm, salt, info))
        val okm = ByteArray(32)
        hkdf.generateBytes(okm, 0, 32)
        return okm
    }

    private fun signBytes(privateKey: PrivateKey, data: ByteArray): Pair<String, String> {
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(privateKey)
        signer.update(data)
        val der = signer.sign()
        return derToHexRs(der)
    }

    private fun verifySignature(publicKey: PublicKey, data: ByteArray, rHex: String, sHex: String): Boolean {
        val der = hexRsToDer(rHex, sHex)
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(publicKey)
        verifier.update(data)
        return verifier.verify(der)
    }

    private fun derToHexRs(der: ByteArray): Pair<String, String> {
        var offset = 3
        val rLen = der[offset++].toInt()
        val rBytes = der.copyOfRange(offset, offset + rLen)
        offset += rLen + 1
        val sLen = der[offset++].toInt()
        val sBytes = der.copyOfRange(offset, offset + sLen)
        val r = BigInteger(1, rBytes).toString(16).padStart(64, '0')
        val s = BigInteger(1, sBytes).toString(16).padStart(64, '0')
        return Pair(r, s)
    }

    private fun hexRsToDer(rHex: String, sHex: String): ByteArray {
        val r = BigInteger(rHex, 16).toByteArray()
        val s = BigInteger(sHex, 16).toByteArray()
        val totalLen = 2 + r.size + 2 + s.size
        val out = ByteArrayOutputStream()
        out.write(0x30)
        out.write(totalLen)
        out.write(0x02)
        out.write(r.size)
        out.write(r)
        out.write(0x02)
        out.write(s.size)
        out.write(s)
        return out.toByteArray()
    }

    private fun computeFileSha256(uri: Uri): String {
        val md = MessageDigest.getInstance("SHA-256")
        val stream = context.contentResolver.openInputStream(uri) ?: return ""
        val buffer = ByteArray(8192)
        var read: Int
        while (stream.read(buffer).also { read = it } != -1) {
            md.update(buffer, 0, read)
        }
        stream.close()
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    private fun computeFileSha256(file: java.io.File): String {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { stream ->
            val buf = ByteArray(8192)
            var r: Int
            while (stream.read(buf).also { r = it } != -1) {
                md.update(buf, 0, r)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }
}