package io.mosip.openID4VP.jwt.jwe

import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.jwt.jwe.encryption.X25519KeyAgreement
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

private val className = JWEHandler::class.simpleName!!

class JWEHandler(
    private val keyEncryptionAlg: String,
    private val contentEncryptionAlg: String,
    private val publicKey: Jwk,
    private val walletNonce: String,
    private val verifierNonce: String
) {

    private val keyAgreement = X25519KeyAgreement()

    fun generateEncryptedResponse(payload: Map<String, Any>): String {
        try {
            val payloadString = io.mosip.openID4VP.common.getObjectMapper().writeValueAsString(payload)
            val payloadData = payloadString.toByteArray(StandardCharsets.UTF_8)

            val publicKeyX = decodeFromBase64Url(publicKey.x)
            val sharedKey = keyAgreement.deriveKey(
                publicKeyX = publicKeyX,
                algorithm = contentEncryptionAlg,
                apu = walletNonce,
                apv = verifierNonce
            )

            val headerMap = keyAgreement.getJWEHeader(
                alg = keyEncryptionAlg,
                enc = contentEncryptionAlg,
                jwk = publicKey,
                apu = walletNonce,
                apv = verifierNonce
            )

            val encodedHeader = encodeToBase64Url(
                io.mosip.openID4VP.common.getObjectMapper().writeValueAsString(headerMap)
                    .toByteArray(StandardCharsets.UTF_8)
            )

            val aad = encodedHeader.toByteArray(StandardCharsets.UTF_8)
            val nonce = ByteArray(12)
            SecureRandom().nextBytes(nonce)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val keySpec = SecretKeySpec(sharedKey, "AES")
            val gcmSpec = GCMParameterSpec(128, nonce)
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
            cipher.updateAAD(aad)
            
            val ciphertextWithTag = cipher.doFinal(payloadData)
            val ciphertext = ciphertextWithTag.copyOfRange(0, ciphertextWithTag.size - 16)
            val tag = ciphertextWithTag.copyOfRange(ciphertextWithTag.size - 16, ciphertextWithTag.size)

            return listOf(
                encodedHeader,
                "", // Encrypted Key is empty for Direct Key Agreement
                encodeToBase64Url(nonce),
                encodeToBase64Url(ciphertext),
                encodeToBase64Url(tag)
            ).joinToString(".")
        } catch (exception: Exception) {
            throw OpenID4VPExceptions.JweEncryptionFailure(className)
        }
    }

    fun decrypt(jwe: String): Map<String, Any> {
        try {
            val parts = jwe.split(".")
            if (parts.size != 5) {
                throw OpenID4VPExceptions.InvalidData("Invalid JWE format", className)
            }

            val encodedHeader = parts[0]
            val iv = decodeFromBase64Url(parts[2])
            val ciphertext = decodeFromBase64Url(parts[3])
            val authTag = decodeFromBase64Url(parts[4])

            val headerMap = io.mosip.openID4VP.common.getObjectMapper().readValue(
                String(decodeFromBase64Url(encodedHeader), StandardCharsets.UTF_8),
                Map::class.java
            ) as Map<String, Any>

            val apu = headerMap["apu"] as? String ?: ""
            val apv = headerMap["apv"] as? String ?: ""

            val sharedKey = keyAgreement.deriveKeyWithExistingEphemeral(
                publicKeyX = decodeFromBase64Url(publicKey.x),
                algorithm = contentEncryptionAlg,
                apu = apu,
                apv = apv
            )

            val aad = encodedHeader.toByteArray(StandardCharsets.UTF_8)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val keySpec = SecretKeySpec(sharedKey, "AES")
            val gcmSpec = GCMParameterSpec(128, iv)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
            cipher.updateAAD(aad)

            val ciphertextWithTag = ciphertext + authTag
            val decryptedData = cipher.doFinal(ciphertextWithTag)

            return io.mosip.openID4VP.common.getObjectMapper().readValue(
                String(decryptedData, StandardCharsets.UTF_8),
                Map::class.java
            ) as Map<String, Any>
        } catch (exception: Exception) {
            throw OpenID4VPExceptions.GenericFailure("JWE decryption failed: ${exception.message}", className)
        }
    }
}