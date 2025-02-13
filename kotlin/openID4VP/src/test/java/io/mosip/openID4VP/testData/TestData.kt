package io.mosip.openID4VP.testData

import io.mosip.openID4VP.authorizationRequest.ClientIdScheme
import io.mosip.openID4VP.dto.VPResponseMetadata.VPResponseMetadata
import io.mosip.openID4VP.dto.VPResponseMetadata.types.LdpVPResponseMetadata
import io.mosip.openID4VP.dto.Verifier

val publicKey = """-----BEGIN RSA PUBLIC KEY-----
        MIICCgKCAgEA0IEd3E5CvLAbGvr/ysYT2TLE7WDrPBHGk8pwGqVvlrrFtZJ9wT8E
        lDNkSfHIgBijphkgSXpVMduwWKidiFFtbqQHgKdr4vdiMKzTy8g0aTpD8T5xPImM
        CC6CUVgp4EZZHkFK3S2guLZAanXLju3WBD4FuBQTl08vP5MlsiseIIanOnTulUDR
        baGIYhONq2kN9UnLIXcv8QPIgroP/n76Ir39EwRd20E4jsNfEriZFthBZKQLNbTz
        GrsVMtpUbHPUlvACrTzXm5RQ1THHDYUa46KmxZfTCKWM2EppaoJlUj1psf3LdlOU
        MBAarn+3QUxYOMLu9vTLvqsk606WNbeuiHarY6lBAec1E6RXMIcVLKBqMy6NjMCK
        Va3ZFvn6/G9JI0U+S8Nn3XpH5nLnyAwim7+l9ZnmqeKTTcnE8oxEuGdP7+VvpyHE
        AF8jilspP0PuBLMNV4eNthKPKPfMvBbFtzLcizqXmSLPx8cOtrEOu+cEU6ckavAS
        XwPgM27JUjeBwwnAhS8lrN3SiJLYCCi1wXjgqFgESNTBhHq+/H5Mb2wxliJQmfzd
        BQOI7kr7ICohW8y2ivCBKGR3dB9j7l77C0o/5pzkHElESdR2f3q+nXfHds2NmoRU
        IGZojdVF+LrGiwRBRUvZMlSKUdsoYVAxz/a5ISGIrWCOd9PgDO5RNNUCAwEAAQ==
        -----END RSA PUBLIC KEY-----"""
val ldpVPResponseMetadata: LdpVPResponseMetadata = LdpVPResponseMetadata(
    "eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ",
    "RsaSignature2018",
    publicKey,
    "https://123",
)
val vpResponsesMetadata: Map<String, VPResponseMetadata> = mapOf("ldp_vc" to ldpVPResponseMetadata)

val clientMetadata = """
    {
  "client_name": "Requester name",
  "logo_uri": "<logo_uri>",
  "authorization_encrypted_response_alg": "ECDH-ES",
  "authorization_encrypted_response_enc": "A256GCM",
  "vp_formats": {
    "mso_mdoc": {
      "alg": [
        "ES256",
        "EdDSA"
      ]
    },
    "ldp_vp": {
      "proof_type": [
        "Ed25519Signature2018",
        "Ed25519Signature2020",
        "RsaSignature2018"
      ]
    }
  }
}
""".trimIndent()

val presentationDefinition = """
    {
      "id": "649d581c-f891-4969-9cd5-2c27385a348f",
      "input_descriptors": [
        {
          "id": "idcardcredential",
          "format": {
            "ldp_vc": {
              "proof_type": [
                "Ed25519Signature2018"
              ]
            }
          },
          "constraints": {
            "fields": [
              {
                "path": [
                  "${'$'}.type"
                ]
              }
            ]
          }
        }
      ]
    }
""".trimIndent()

val didResponse = """
    {
      "@context": "https://w3id.org/did-resolution/v1",
      "didDocument": {
        "assertionMethod": [
          "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0"
        ],
        "service": [],
        "id": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
        "verificationMethod": [
          {
            "publicKey": "IKXhA7W1HD1sAl+OfG59VKAqciWrrOL1Rw5F+PGLhi4=",
            "controller": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
            "id": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0",
            "type": "Ed25519VerificationKey2020",
            "@context": "https://w3id.org/security/suites/ed25519-2020/v1"
          }
        ],
        "@context": [
          "https://www.w3.org/ns/did/v1"
        ],
        "alsoKnownAs": [],
        "authentication": [
          "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0"
        ]
      },
      "didResolutionMetadata": {
        "driverDuration": 19,
        "contentType": "application/did+ld+json",
        "pattern": "^(did:web:.+)${'$'}",
        "driverUrl": "http://uni-resolver-driver-did-uport:8081/1.0/identifiers/",
        "duration": 19,
        "did": {
          "didString": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
          "methodSpecificId": "mosip.github.io:inji-mock-services:openid4vp-service:docs",
          "method": "web"
        },
        "didUrl": {
          "path": null,
          "fragment": null,
          "query": null,
          "didUrlString": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
          "parameters": null,
          "did": {
            "didString": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
            "methodSpecificId": "mosip.github.io:inji-mock-services:openid4vp-service:docs",
            "method": "web"
          }
        }
      },
      "didDocumentMetadata": {}
    }
""".trimIndent()

val trustedVerifiers: List<Verifier> = listOf(
    Verifier(
        "https://verifier.env1.net", listOf(
            "https://verifier.env1.net/responseUri", "https://verifier.env2.net/responseUri"
        )
    ), Verifier(
        "https://verifier.env2.net", listOf(
            "https://verifier.env3.net/responseUri", "https://verifier.env2.net/responseUri"
        )
    )
)

val authRequestParamsByReference = listOf(
    "client_id",
    "client_id_scheme",
    "request_uri",
    "request_uri_method"
)


val authRequestWithRedirectUriByValue = listOf(
    "client_id",
    "client_id_scheme",
    "redirect_uri",
    "presentation_definition",
    "response_type",
    "nonce",
    "state",
    "client_metadata"
)

val authRequestWithPreRegisteredByValue = listOf(
    "client_id",
    "client_id_scheme",
    "response_mode",
    "response_uri",
    "presentation_definition",
    "response_type",
    "nonce",
    "state",
    "client_metadata"
)

val authRequestWithDidByValue = listOf(
    "client_id",
    "client_id_scheme",
    "response_mode",
    "response_uri",
    "presentation_definition",
    "response_type",
    "nonce",
    "state",
    "client_metadata"
)

val authorisationRequestListToClientIdSchemeMap = mapOf(
    ClientIdScheme.DID to authRequestWithDidByValue,
    ClientIdScheme.REDIRECT_URI to authRequestWithRedirectUriByValue,
    ClientIdScheme.PRE_REGISTERED to authRequestWithPreRegisteredByValue
)

val clientIdAndSchemeOfDid = mapOf(
    "client_id" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
    "client_id_scheme" to ClientIdScheme.DID.value
)

val clientIdAndSchemeOfPreRegistered = mapOf(
    "client_id" to "https://verifier.env1.net",
    "client_id_scheme" to ClientIdScheme.PRE_REGISTERED.value
)

val clientIdAndSchemeOfReDirectUri = mapOf(
    "client_id" to "https://mock-verifier.com",
    "client_id_scheme" to "redirect_uri",
)