package io.mosip.openID4VP.authorizationResponse.jwe

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEEncrypter
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.crypto.X25519Encrypter
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.CurveBasedJWK
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.jwe.exception.JWEExceptions.UnsupportedEncryptionAlgorithm
import io.mosip.openID4VP.jwe.exception.JWEExceptions.UnsupportedKeyExchangeAlgorithm

private val className = JWEHandler::class.simpleName!!

class JWEHandler(val clientMetadata: ClientMetadata) {

    fun createResponse(bodyParams: Map<String, String>): String {

        val (alg, enc, jwk) = fetchJWECreationFields()

        val header = JWEHeader(alg, enc)

        val claimsBuilder = JWTClaimsSet.Builder()
        bodyParams.forEach { (key, value) ->
            claimsBuilder.claim(key, value)
        }
        val claimsSet = claimsBuilder.build()

        val verifierPublicKey = getOctetPublicKey(jwk)
        val encrypter = X25519Encrypter(verifierPublicKey as OctetKeyPair)
        val jwt = EncryptedJWT(header, claimsSet)
        try {
            jwt.encrypt(encrypter)
            println("JWE:  ${jwt.serialize()}")

            return jwt.serialize()
        } catch (exception: Exception) {
            throw Logger.handleException(
                exceptionType = "JWTEncryptionFailure", //TODO : add the exception
                message = exception.message,
                className = className
            )
        }


    }


    private fun fetchJWECreationFields(): Triple<JWEAlgorithm, EncryptionMethod, Jwk> {
        val alg = clientMetadata.authorizationEncryptedResponseAlg!!
        val enc = clientMetadata.authorizationEncryptedResponseEnc!!
        val jwk = clientMetadata.jwks?.let {
            it.keys.find { key -> key.alg == alg }
        }!!
        return Triple(getAlgorithm(alg), getEncryption(enc), jwk)
    }

    private fun getOctetPublicKey(jwk: Jwk): CurveBasedJWK {

        return OctetKeyPair.Builder(
            Curve(jwk.crv),
            Base64URL.from(jwk.x)
        )
            .keyID(jwk.kid)
            .algorithm(Algorithm.parse(jwk.alg))
            .keyUse(KeyUse(jwk.use))
            .build()
            .toPublicJWK()
    }


    //TODO: revisit the exception
    private fun getAlgorithm(alg: String): JWEAlgorithm {
        return when (alg) {
            "ECDH-ES" -> JWEAlgorithm.ECDH_ES
            else -> throw UnsupportedKeyExchangeAlgorithm()
        }
    }

    //TODO: revisit the exception
    private fun getEncryption(enc: String): EncryptionMethod {
        return when (enc) {
            "A256GCM" -> EncryptionMethod.A256GCM
            else -> throw UnsupportedEncryptionAlgorithm()
        }
    }

}