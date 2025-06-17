package io.mosip.sampleapp.utils;

import com.google.gson.JsonObject
import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.*
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.*
import java.security.*
import java.security.interfaces.*
import java.util.*

enum class KeyType {
    RSA, ES256, Ed25519
}

data class SignedVPJWT(
    val jwt: String,
    val publicJWK: String,
    val algorithm: String
)

object VPTokenSigner {

    private fun signVPTokenWithRSAorEC(
        keyPair: KeyPair,
        keyType: KeyType,
        vpPayload: Map<String, Any>
    ): SignedVPJWT {
        val jwk: JWK
        val signer: JWSSigner
        val alg: JWSAlgorithm

        when (keyType) {
            KeyType.RSA -> {
                val rsaKey = RSAKey.Builder(keyPair.public as RSAPublicKey)
                    .privateKey(keyPair.private as RSAPrivateKey)
                    .keyID(UUID.randomUUID().toString())
                    .build()
                jwk = rsaKey
                signer = RSASSASigner(rsaKey)
                alg = JWSAlgorithm.RS256
            }
            KeyType.ES256 -> {
                val ecKey = ECKey.Builder(Curve.P_256, keyPair.public as ECPublicKey)
                    .privateKey(keyPair.private as ECPrivateKey)
                    .keyID(UUID.randomUUID().toString())
                    .build()
                jwk = ecKey
                signer = ECDSASigner(ecKey)
                alg = JWSAlgorithm.ES256
            }

            else -> throw IllegalArgumentException("Unsupported key type: $keyType")
        }

        val claimsSet = JWTClaimsSet.Builder()
            .issuer("did:jwk")
            .issueTime(Date())
            .claim("vp", vpPayload)
            .build()

        val signedJWT = SignedJWT(
            JWSHeader.Builder(alg).keyID(jwk.keyID).type(JOSEObjectType.JWT).build(),
            claimsSet
        )
        signedJWT.sign(signer)

        return SignedVPJWT(signedJWT.serialize(), jwk.toPublicJWK().toJSONString(), alg.name)
    }

    private fun signVPTokenWithEd25519(
        jwk: OctetKeyPair,
        vpPayload: Map<String, Any>
    ): SignedVPJWT {
        val signer = Ed25519Signer(jwk)
        val claimsSet = JWTClaimsSet.Builder()
            .issuer("did:jwk")
            .issueTime(Date())
            .claim("vp", vpPayload)
            .build()

        val signedJWT = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .keyID(jwk.keyID)
                .type(JOSEObjectType.JWT)
                .build(),
            claimsSet
        )
        signedJWT.sign(signer)

        return SignedVPJWT(signedJWT.serialize(), jwk.toPublicJWK().toJSONString(), JWSAlgorithm.EdDSA.name)
    }

    fun signVpToken(
        keyType: KeyType,
        mapPayload: Map<String, Any>
    ) = when (keyType) {
        KeyType.RSA, KeyType.ES256 -> {
            val keyPair = SampleKeyGenerator.generateKeyPair(keyType) as KeyPair
            signVPTokenWithRSAorEC(keyPair, keyType, mapPayload)
        }

        KeyType.Ed25519 -> {
            val jwk = SampleKeyGenerator.generateKeyPair(keyType) as OctetKeyPair
            signVPTokenWithEd25519(jwk, mapPayload)
        }
    }

    fun signDeviceAuthentication(
        keyPair: KeyPair,
        keyType: KeyType,
        deviceAuthBytes: ByteArray
    ): SignedVPJWT {
        val header = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build()
        val payload = Payload(deviceAuthBytes)
        val jwsObject = JWSObject(header, payload)

        val signer = when (keyType) {
            KeyType.ES256 -> ECDSASigner(keyPair.private as ECPrivateKey)
            KeyType.RSA -> RSASSASigner(keyPair.private)
            else -> throw Exception("Unsupported key type for signing device authentication")
        }
        jwsObject.sign(signer)

        return SignedVPJWT(
            jwt = jwsObject.serialize(),
            algorithm = jwsObject.header.algorithm.name,
            publicJWK = ""
        )
    }
}



object SampleKeyGenerator {

    val HOLDER_ID = generateEd25519Jwk()
    const val SIGNATURE_SUITE = "JsonWebSignature2020"

    fun generateKeyPair(keyType: KeyType): Any {
        return when (keyType) {
            KeyType.RSA -> {
                val keyGen = KeyPairGenerator.getInstance("RSA")
                keyGen.initialize(2048)
                keyGen.generateKeyPair()
            }
            KeyType.ES256 -> {
                val keyGen = KeyPairGenerator.getInstance("EC")
                keyGen.initialize(Curve.P_256.toECParameterSpec())
                keyGen.generateKeyPair()
            }
            KeyType.Ed25519 -> {
                generateEd25519KeyPair()
            }
        }
    }

    private fun generateEd25519KeyPair(): OctetKeyPair {
        return OctetKeyPairGenerator(Curve.Ed25519)
            .keyUse(KeyUse.SIGNATURE)
            .keyIDFromThumbprint(true)
            .generate()
    }

    private fun generateEd25519Jwk(): String {
        return "did:jwk:${Base64URL.encode(generateEd25519KeyPair().toPublicJWK().toJSONString().toByteArray())}"
    }

}

object MdocKeyManager {
    fun getIssuerAuthenticationAlgorithmForMdocVC(proofType: Int): String {
        return when (proofType) {
            -7 -> "ES256"
            else -> ""
        }
    }

    fun getMdocAuthenticationAlgorithm(issuerAuth: JsonObject): String {
        val deviceKey = issuerAuth.getAsJsonObject("deviceKeyInfo")?.getAsJsonObject("deviceKey") ?: return ""

        val keyType = deviceKey["1"]?.asInt
        val curve = deviceKey["-1"]?.asInt

        return if (keyType == ProtectedAlgorithm.EC2 && curve == ProtectedCurve.P256) "ES256" else ""
    }
    private object ProtectedAlgorithm {
        const val EC2 = 2
    }

    private object ProtectedCurve {
        const val P256 = 1
    }
}
