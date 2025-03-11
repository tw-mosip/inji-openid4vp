package io.mosip.openID4VP.jwt.jwe

import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.jwt.jwe.encryption.EncryptionProvider
import io.mosip.openID4VP.jwt.jwe.keyExchange.KeyExchangeProvider
import io.mosip.openID4VP.common.Logger

private val className = JWEHandler::class.simpleName!!

class JWEHandler(
    private val keyEncryptionAlg: String,
    private val contentEncryptionAlg: String,
    private val publicKey: Jwk
) {

    fun generateEncryptedResponse(payload: Map<String, Any>): String {

        val algorithm =
            KeyExchangeProvider.getAlgorithm(keyEncryptionAlg)
        val encryptionMethod =
            EncryptionProvider.getMethod(contentEncryptionAlg)

        val encrypter = EncryptionProvider.getEncrypter(publicKey)

        val header = JWEHeader(algorithm, encryptionMethod,
            null, null, null, null, null, null, null, null, null, publicKey.kid,
            null, null, null, null, null, 0,
            null, null,
            null, null, null)

        val claimsSet = JWTClaimsSet.Builder().apply {
            payload.forEach { (key, value) -> claim(key, value) }
        }.build()

        try {
            val jwt = EncryptedJWT(header, claimsSet)
            jwt.encrypt(encrypter)
            return jwt.serialize()
        } catch (exception: Exception) {
            throw Logger.handleException(
                exceptionType = "JWTEncryptionFailure",
                message = exception.message,
                className = className
            )
        }
    }
}