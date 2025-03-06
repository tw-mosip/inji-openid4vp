package io.mosip.openID4VP.authorizationResponse.jwe

import com.nimbusds.jose.JWEHeader
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationResponse.jwe.encryption.EncryptionProvider
import io.mosip.openID4VP.authorizationResponse.jwe.keyExchange.KeyExchangeProvider
import io.mosip.openID4VP.common.Logger

private val className = JWEProcessor::class.simpleName!!

class JWEProcessor(private val clientMetadata: ClientMetadata) {

    fun generateEncryptedResponse(payload: Map<String, Any>): String {

        val algorithm =
            KeyExchangeProvider.getAlgorithm(clientMetadata.authorizationEncryptedResponseAlg!!)
        val encryptionMethod =
            EncryptionProvider.getMethod(clientMetadata.authorizationEncryptedResponseEnc!!)
        val jwk =
            clientMetadata.jwks?.keys?.find { it.alg == clientMetadata.authorizationEncryptedResponseAlg }!!

        val header = JWEHeader(algorithm, encryptionMethod,
            null, null, null, null, null, null, null, null, null, jwk.kid,
            null, null, null, null, null, 0,
            null, null,
            null, null, null)

        val claimsSet = JWTClaimsSet.Builder().apply {
            payload.forEach { (key, value) -> claim(key, value) }
        }.build()
        try {
            val encrypter = EncryptionProvider.getEncrypter(jwk)
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