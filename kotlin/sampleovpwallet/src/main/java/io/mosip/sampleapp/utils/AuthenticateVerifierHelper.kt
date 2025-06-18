package io.mosip.sampleapp.utils

import com.fasterxml.jackson.databind.PropertyNamingStrategies
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import io.mosip.openID4VP.authorizationRequest.Verifier
import io.mosip.openID4VP.authorizationRequest.WalletMetadata

object AuthenticateVerifierHelper {
    fun extractWalletMetadata(): WalletMetadata {
        val hardcodedMetadataJson = """
            {
              "presentation_definition_uri_supported": true,
              "vp_formats_supported": {
                "ldp_vc": {
                  "alg_values_supported": [
                    "Ed25519Signature2018",
                    "Ed25519Signature2020",
                    "RSASignature2018"
                  ]
                },
                "mso_mdoc": {
                  "alg_values_supported": ["ES256"]
                }
              },
              "client_id_schemes_supported": ["redirect_uri", "did", "pre-registered"],
              "request_object_signing_alg_values_supported": ["EdDSA"],
              "authorization_encryption_alg_values_supported": ["ECDH-ES"],
              "authorization_encryption_enc_values_supported": ["A256GCM"]
            }
            """.trimIndent()

        val objectMapper = jacksonObjectMapper()

        return objectMapper.readValue(hardcodedMetadataJson)
    }

    fun extractVerifiers(): List<Verifier> {
        val hardcodedVerifierJson = """
        [
            {
              "client_id": "https://localhost:3000",
              "response_uris": [
                "https://localhost:3000/v1/verify/vp-submission/direct-post"
              ]
            }
        ]
    """.trimIndent()

        val objectMapper = jacksonObjectMapper()
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)

        return objectMapper.readValue(hardcodedVerifierJson)
    }
}