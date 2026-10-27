package com.pasa.android;

import android.content.Context;
import android.net.Uri;
import android.util.Base64;
import kotlinx.coroutines.Dispatchers;
import kotlinx.coroutines.withContext;
import okhttp3.MediaType.Companion.toMediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody.Companion.toRequestBody;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import kotlin.math.ceil;

class PasaClient(private val context: Context) {

    private val httpClient = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .writeTimeout(60, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .build()

    // Identidad permanente P-256
    val identityKeyPair: KeyPair by lazy { generateP256KeyPair() }
    val deviceId = "Android-Device"

    companion object {
        private const val MAGIC = "PASA_V1"
        private const val CHUNK_SIZE = 256 * 1024 // 256 KiB
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
        return String.format("%06d", num % 1000000)
    }

    private fun compareByteArrays(a: ByteArray, b: ByteArray): Int {
        val minLen = minOf(a.size, b.size)
        for (i in 0 until minLen) {
            val cmp = (a[i].toInt() and 0xFF).compareTo(b[i].toInt() and 0xFF)
            if (cmp != 0) return cmp
        }
        return a.size.compareTo(b.size)
    }

    // --- Protocolo de Envío ---

    suspend fun pairWithMac(serverBaseUrl: String): Pair<String, ECPublicKey> = withContext(Dispatchers.IO) {
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

        // 2. /pair/confirm
        val confirmJson = JSONObject().apply {
            put("device_id", deviceId)
            put("confirmed", true)
        }
        val confirmReq = Request.Builder()
                .url("$serverBaseUrl/api/v1/pair/confirm")
                .post(confirmJson.toString().toRequestBody("application/json".toMediaType()))
                .build()

        httpClient.newCall(confirmReq).execute()

        Pair(sasCode, macPublicKey)
    }

    suspend fun sendFile(
            serverBaseUrl: String,
            macIdentityKey: ECPublicKey,
            fileUri: Uri,
            fileName: String,
            fileSize: Long,
            onProgress: (Int) -> Unit
    ) = withContext(Dispatchers.IO) {
        val transferId = UUID.randomUUID().toString()

        // 1. Calcular SHA-256 del archivo original
        val fileSha256 = computeFileSha256(fileUri)

        // 2. /transfer/request
        val reqJson = JSONObject().apply {
            put("device_id", deviceId)
            put("transfer_id", transferId)
            put("file_name", fileName)
            put("file_size_bytes", fileSize)
            put("total_chunks", maxOf(1, ceil((fileSize + 1024).toDouble() / CHUNK_SIZE).toInt()))
            put("sha256_expected", fileSha256)
        }

        val requestCall = Request.Builder()
                .url("$serverBaseUrl/api/v1/transfer/request")
                .post(reqJson.toString().toRequestBody("application/json".toMediaType()))
                .build()
        httpClient.newCall(requestCall).execute()

        // 3. Handshake ECDHE
        val ephKeyPair = generateP256KeyPair()
        val ephPubBytes = getPublicKeyUncompressedBytes(ephKeyPair.public as ECPublicKey)
        val ephPubB64 = Base64.encodeToString(ephPubBytes, Base64.NO_WRAP)

        // Firmar clave efímera con identidad permanente
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

        // Validar firma de la Mac
        val validMacSig = verifySignature(
                macIdentityKey,
                macEphPubBytes,
                hsData.getString("signature_r"),
                hsData.getString("signature_s")
        )
        if (!validMacSig) throw SecurityException("Firma de la Mac inválida (Posible MITM)")

        // Derivar K_session (AES 256)
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(ephKeyPair.private)
        ka.doPhase(macEphPub, true)
        val sharedSecret = ka.generateSecret()

        val (first, second) = if (compareByteArrays(ephPubBytes, macEphPubBytes) <= 0)
            Pair(ephPubBytes, macEphPubBytes) else Pair(macEphPubBytes, ephPubBytes)
        val salt = first + second

        val kSession = deriveHkdf(sharedSecret, salt, "pasa-session-v1".toByteArray(), 32)

        // 4. Cifrar con formato LFSS y transmitir
        val encryptedData = encryptStreamLfss(fileUri, kSession)
        val totalChunks = maxOf(1, ceil(encryptedData.size.toDouble() / CHUNK_SIZE).toInt())

        for (i in 0 until totalChunks) {
            val from = i * CHUNK_SIZE
            val to = minOf(from + CHUNK_SIZE, encryptedData.size)
            val chunk = encryptedData.copyOfRange(from, to)

            val chunkReq = Request.Builder()
                    .url("$serverBaseUrl/api/v1/transfer/chunk")
                    .header("Content-Type", "application/octet-stream")
                    .header("X-Transfer-Id", transferId)
                    .header("X-Chunk-Index", i.toString())
                    .post(chunk.toRequestBody("application/octet-stream".toMediaType()))
                    .build()

            httpClient.newCall(chunkReq).execute()
            onProgress(((i + 1).toDouble() / totalChunks * 100).toInt())
        }

        // 5. /transfer/finalize
        val finJson = JSONObject().apply { put("transfer_id", transferId) }
        val finReq = Request.Builder()
                .url("$serverBaseUrl/api/v1/transfer/finalize")
                .post(finJson.toString().toRequestBody("application/json".toMediaType()))
                .build()

        val finRes = httpClient.newCall(finReq).execute()
        val finData = JSONObject(finRes.body?.string() ?: "{}")
        if (!finData.optBoolean("integrity_valid", false)) {
            throw SecurityException("Error de integridad SHA-256 en la Mac")
        }
    }

    private fun encryptStreamLfss(uri: Uri, kSession: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        val secureRandom = SecureRandom()

        val salt = ByteArray(16).also { secureRandom.nextBytes(it) }
        val maskNonce = ByteArray(12).also { secureRandom.nextBytes(it) }

        // Derivar K_file
        val kFile = deriveHkdf(kSession, salt, byteArrayOf(), 32)
        val secretKey = SecretKeySpec(kFile, "AES")

        // Escribir cabecera LFSS
        out.write(MAGIC.toByteArray(Charsets.US_ASCII))
        out.write(salt)
        out.write(maskNonce)

        val inputStream: InputStream = context.contentResolver.openInputStream(uri)
                ?: throw Exception("No se pudo leer el archivo")

        val buffer = ByteArray(64 * 1024)
        var chunkIdx = 0
        var bytesRead: Int

        while (inputStream.read(buffer).also { bytesRead = it } != -1) {
            val nonce = computeNonce(maskNonce, chunkIdx)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, nonce))

            val aad = ByteBuffer.allocate(11)
                    .put(MAGIC.toByteArray(Charsets.US_ASCII))
                    .putInt(chunkIdx)
                    .array()
            cipher.updateAAD(aad)

            val ciphertextWithTag = cipher.doFinal(buffer, 0, bytesRead)
            out.write(ByteBuffer.allocate(4).putInt(ciphertextWithTag.size).array())
            out.write(ciphertextWithTag)
            chunkIdx++
        }
        inputStream.close()
        return out.toByteArray()
    }

    private fun computeNonce(maskNonce: ByteArray, index: Int): ByteArray {
        val nonce = maskNonce.copyOf()
        val idxBytes = ByteBuffer.allocate(4).putInt(index).array()
        for (i in 0..3) {
            nonce[8 + i] = (nonce[8 + i].toInt() xor idxBytes[i].toInt()).toByte()
        }
        return nonce
    }

    private fun deriveHkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(ikm, salt, info))
        val okm = ByteArray(length)
        hkdf.generateBytes(okm, 0, length)
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
}