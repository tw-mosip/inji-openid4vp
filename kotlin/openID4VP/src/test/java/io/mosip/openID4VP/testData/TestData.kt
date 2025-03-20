package io.mosip.openID4VP.testData

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_METADATA
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.NONCE
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.PRESENTATION_DEFINITION
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.PRESENTATION_DEFINITION_URI
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.REDIRECT_URI
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.REQUEST_URI
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.REQUEST_URI_METHOD
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_MODE
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_TYPE
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_URI
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.STATE
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponse
import io.mosip.openID4VP.authorizationResponse.models.unsignedVPToken.types.UnsignedLdpVPToken
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PathNested
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldpVp.LdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldpVp.Proof
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.dto.vpResponseMetadata.types.LdpVPResponseMetadata
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.dto.vpResponseMetadata.VPResponseMetadata

const val requestUrl = "https://mock-verifier.com/verifier/get-auth-request-obj"

const val publicKey = """-----BEGIN RSA PUBLIC KEY-----
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
val vpResponsesMetadata: Map<FormatType, VPResponseMetadata> =
    mapOf(FormatType.LDP_VC to ldpVPResponseMetadata)

val unsignedLdpVPToken: UnsignedLdpVPToken = UnsignedLdpVPToken(
    context = listOf("https://www.w3.org/2018/credentials/v1"),
    type = listOf("VerifiablePresentation"),
    verifiableCredential = listOf("credential1", "credential2", "credential3"),
    id = "649d581c-f291-4969-9cd5-2c27385a348f",
    holder = "",
)

val unsignedVPTokens = mapOf(FormatType.LDP_VC to unsignedLdpVPToken)

val clientMetadataMap = mapOf(
    "client_name" to "Requester name",
    "logo_uri" to "<logo_uri>",
    "authorization_encrypted_response_alg" to "ECDH-ES",
    "authorization_encrypted_response_enc" to "A256GCM",
    "vp_formats" to mapOf(
        "mso_mdoc" to mapOf(
            "alg" to listOf("ES256", "EdDSA")
        ),
        "ldp_vp" to mapOf(
            "proof_type" to listOf(
                "Ed25519Signature2018",
                "Ed25519Signature2020",
                "RsaSignature2018"
            )
        )
    )
)

val clientMetadataString = """{
  "client_name": "Requester name",
  "logo_uri": "<logo_uri>",
  "authorization_encrypted_response_alg": "ECDH-ES",
  "authorization_encrypted_response_enc": "A256GCM",
  "jwks": {
    "keys": [
      {
        "kty": "OKP",
        "crv": "X25519",
        "use": "enc",
        "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
        "alg": "ECDH-ES",
        "kid": "ed-key1"
      }
    ]
  },
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

val presentationDefinitionMap = mapOf(
    "id" to "649d581c-f891-4969-9cd5-2c27385a348f",
    "input_descriptors" to listOf(
        mapOf(
            "id" to "idcardcredential",
            "format" to mapOf(
                "ldp_vc" to mapOf(
                    "proof_type" to listOf("Ed25519Signature2018")
                )
            ),
            "constraints" to mapOf(
                "fields" to listOf(
                    mapOf(
                        "path" to listOf("\$.type") // Escaped '$' as Kotlin requires '\$'
                    )
                )
            )
        )
    )
)

val presentationDefinitionString = """
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
        "mock-client", listOf(
            "https://mock-verifier.net/responseUri", "https://verifier.env2.net/responseUri"
        )
    ), Verifier(
        "mock-client2", listOf(
            "https://verifier.env3.net/responseUri", "https://verifier.env2.net/responseUri"
        )
    )
)

val authRequestParamsByReference = listOf(
    CLIENT_ID.value,
    REQUEST_URI.value,
    REQUEST_URI_METHOD.value
)

val authRequestWithRedirectUriByValue = listOf(
    CLIENT_ID.value,
    RESPONSE_URI.value,
    RESPONSE_MODE.value,
    PRESENTATION_DEFINITION.value,
    RESPONSE_TYPE.value,
    NONCE.value,
    STATE.value,
    CLIENT_METADATA.value
)

val authRequestWithPreRegisteredByValue = listOf(
    CLIENT_ID.value,
    RESPONSE_MODE.value,
    RESPONSE_URI.value,
    PRESENTATION_DEFINITION.value,
    RESPONSE_TYPE.value,
    NONCE.value,
    STATE.value,
    CLIENT_METADATA.value
)

val authRequestWithDidByValue = listOf(
    CLIENT_ID.value,
    RESPONSE_MODE.value,
    RESPONSE_URI.value,
    PRESENTATION_DEFINITION.value,
    RESPONSE_TYPE.value,
    NONCE.value,
    STATE.value,
    CLIENT_METADATA.value
)

val requestParams: Map<String, String> = mapOf(
    REDIRECT_URI.value to "https://mock-verifier.com",
    RESPONSE_URI.value to "https://mock-verifier.net/responseUri",
    REQUEST_URI.value to requestUrl,
    REQUEST_URI_METHOD.value to "get",
    PRESENTATION_DEFINITION.value to presentationDefinitionString,
    PRESENTATION_DEFINITION_URI.value to "https://mock-verifier.com/verifier/get-presentation-definition",
    RESPONSE_TYPE.value to "vp_token",
    RESPONSE_MODE.value to "direct_post",
    NONCE.value to "VbRRB/LTxLiXmVNZuyMO8A==",
    STATE.value to "+mRQe1d6pBoJqF6Ab28klg==",
    CLIENT_METADATA.value to clientMetadataString
)

val authorisationRequestListToClientIdSchemeMap = mapOf(
    ClientIdScheme.DID to authRequestWithDidByValue,
    ClientIdScheme.REDIRECT_URI to authRequestWithRedirectUriByValue,
    ClientIdScheme.PRE_REGISTERED to authRequestWithPreRegisteredByValue
)

val clientIdOfDid = mapOf(
    CLIENT_ID.value to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
)

val clientIdOfPreRegistered = mapOf(
    CLIENT_ID.value to "mock-client",
)

val clientIdOfReDirectUri = mapOf(
    CLIENT_ID.value to "${REDIRECT_URI.value}:https://mock-verifier.net/responseUri",
)

val clientMetadataPresentationDefinitionMap = mapOf(
    PRESENTATION_DEFINITION.value to presentationDefinitionMap,
    CLIENT_METADATA.value to clientMetadataMap
)


val authorizationRequestForResponseModeJWT = AuthorizationRequest(
    clientId = "https://injiverify.dev2.mosip.net",
    responseType = "vp_token",
    responseMode = "direct_post.jwt",
    presentationDefinition = deserializeAndValidate(
        presentationDefinitionString,
        PresentationDefinitionSerializer
    ),
    responseUri = "https://mock-verifier.com/response-uri",
    redirectUri = null,
    nonce = "bMHvX1HGhbh8zqlSWf/fuQ==",
    state = "fsnC8ixCs6mWyV+00k23Qg==",
    clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataSerializer)
)

val authorizationRequest = AuthorizationRequest(
    clientId = "https://mock-verifier.com",
    responseType = "vp_token",
    responseMode = "direct_post",
    presentationDefinition = deserializeAndValidate(
        presentationDefinitionMap,
        PresentationDefinitionSerializer
    ),
    responseUri = "https://mock-verifier.com",
    redirectUri = null,
    nonce = "bMHvX1HGhbh8zqlSWf/fuQ==",
    state = "fsnC8ixCs6mWyV+00k23Qg==",
    clientMetadata = deserializeAndValidate(clientMetadataMap, ClientMetadataSerializer)
)

val vpToken = VPTokenType.VPTokenElement(
    LdpVPToken(
        context = listOf("context"),
        type = listOf("type"),
        verifiableCredential = listOf("VC1"),
        id = "id",
        holder = "holder",
        proof = Proof(
            type = "type",
            created = "time",
            challenge = "challenge",
            domain = "domain",
            jws = "eryy....ewr",
            proofPurpose = "authentication",
            verificationMethod = "did:example:holder#key-1"
        )
    )
)

val presentationSubmission = PresentationSubmission(
    id = "ps_id",
    definitionId = "client_id",
    descriptorMap = listOf(
        DescriptorMap(
            id = "input_descriptor_1",
            format = "ldp_vp",
            path = "$",
            pathNested = PathNested(
                id = "input_descriptor_1",
                format = "ldp_vp",
                path = "$.verifiableCredential[0]"
            )
        )
    )
)
val authorizationResponse = AuthorizationResponse(
    presentationSubmission = presentationSubmission,
    vpToken = vpToken,
    state = "state"
)