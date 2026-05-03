package io.mosip.openID4VP.jwt.jwe.encryption

import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom

class X25519KeyAgreement {
    private val className = X25519KeyAgreement::class.simpleName!!
    private var ephemeralPrivateKey: X25519PrivateKeyParameters? = null
    private var ephemeralPublicKey: X25519PublicKeyParameters? = null

    fun deriveKey(
        publicKeyX: ByteArray,
        algorithm: String = "A256GCM",
        apu: String,
        apv: String
    ): ByteArray {
        return deriveKeyInternal(publicKeyX, algorithm, apu, apv, generateNewEphemeral = true)
    }

    fun deriveKeyWithExistingEphemeral(
        publicKeyX: ByteArray,
        algorithm: String = "A256GCM",
        apu: String,
        apv: String
    ): ByteArray {
        return deriveKeyInternal(publicKeyX, algorithm, apu, apv, generateNewEphemeral = false)
    }

    private fun deriveKeyInternal(
        publicKeyX: ByteArray,
        algorithm: String,
        apu: String,
        apv: String,
        generateNewEphemeral: Boolean
    ): ByteArray {
        try {
            val privKey: X25519PrivateKeyParameters
            if (generateNewEphemeral) {
                val secureRandom = SecureRandom()
                privKey = X25519PrivateKeyParameters(secureRandom)
                val pubKey = privKey.generatePublicKey()
                ephemeralPrivateKey = privKey
                ephemeralPublicKey = pubKey
            } else {
                privKey = ephemeralPrivateKey
                    ?: throw IllegalStateException("No ephemeral key available for decryption")
            }

            val agreement = X25519Agreement()
            agreement.init(privKey)
            
            val verifierPubKey = X25519PublicKeyParameters(publicKeyX, 0)
            val sharedSecret = ByteArray(agreement.agreementSize)
            agreement.calculateAgreement(verifierPubKey, sharedSecret, 0)

            val algorithmID = algorithm.toByteArray(Charsets.UTF_8)
            val partyUInfo = decodeFromBase64Url(apu)
            val partyVInfo = decodeFromBase64Url(apv)

            val keyLength = getKeyLength(algorithm)
            
            // Convert key length (in bits) to big-endian bytes (4 bytes)
            val suppPubInfo = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(keyLength * 8).array()

            return concatKDF(
                sharedSecret = sharedSecret,
                keyLength = keyLength,
                algorithmID = algorithmID,
                partyUInfo = partyUInfo,
                partyVInfo = partyVInfo,
                suppPubInfo = suppPubInfo
            )
        } catch (e: Exception) {
            throw OpenID4VPExceptions.GenericFailure("Key agreement failed: ${e.message}", className)
        }
    }

    private fun concatKDF(
        sharedSecret: ByteArray,
        keyLength: Int,
        algorithmID: ByteArray,
        partyUInfo: ByteArray,
        partyVInfo: ByteArray,
        suppPubInfo: ByteArray
    ): ByteArray {
        val otherInfo = ByteBuffer.allocate(4 + algorithmID.size + 4 + partyUInfo.size + 4 + partyVInfo.size + suppPubInfo.size).order(ByteOrder.BIG_ENDIAN).apply {
            putInt(algorithmID.size)
            put(algorithmID)
            putInt(partyUInfo.size)
            put(partyUInfo)
            putInt(partyVInfo.size)
            put(partyVInfo)
            put(suppPubInfo)
        }.array()

        val derivedKey = ByteArray(keyLength)
        var counter = 1
        var bytesGenerated = 0
        val md = MessageDigest.getInstance("SHA-256")

        while (bytesGenerated < keyLength) {
            md.reset()
            val ctrBytes = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(counter).array()
            md.update(ctrBytes)
            md.update(sharedSecret)
            md.update(otherInfo)
            
            val hash = md.digest()
            val bytesToCopy = minOf(hash.size, keyLength - bytesGenerated)
            System.arraycopy(hash, 0, derivedKey, bytesGenerated, bytesToCopy)
            
            bytesGenerated += bytesToCopy
            counter++
        }

        return derivedKey
    }

    fun getEphemeralPublicKey(): Map<String, Any>? {
        return ephemeralPublicKey?.let {
            mapOf(
                "kty" to "OKP",
                "crv" to "X25519",
                "x" to encodeToBase64Url(it.encoded)
            )
        }
    }

    fun getJWEHeader(
        alg: String,
        enc: String,
        jwk: Jwk,
        apu: String,
        apv: String
    ): Map<String, Any> {
        val header = mutableMapOf<String, Any>(
            "alg" to alg,
            "enc" to enc,
            "kid" to (jwk.kid ?: ""),
            "apu" to apu,
            "apv" to apv
        )
        getEphemeralPublicKey()?.let { header["epk"] = it }
        return header
    }

    private fun getKeyLength(algorithm: String): Int {
        return when (algorithm) {
            "A256GCM" -> 32
            else -> throw OpenID4VPExceptions.UnsupportedKeyExchangeAlgorithm(className)
        }
    }
}
