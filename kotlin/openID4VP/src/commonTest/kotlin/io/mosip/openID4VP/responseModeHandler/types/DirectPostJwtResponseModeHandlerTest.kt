package io.mosip.openID4VP.responseModeHandler.types

import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest
import io.mosip.openID4VP.authorizationRequest.LdpVpFormatSupported
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwks
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataDraft23Serializer
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationResponse.AuthorizationErrorResponse
import io.mosip.openID4VP.constants.EncryptionMethod
import io.mosip.openID4VP.constants.EncryptionAlgorithm
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.ProofType
import io.mosip.openID4VP.constants.ContentType
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.dcql.query.CredentialQuery
import io.mosip.openID4VP.dcql.query.DCQLQuery
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.*
import io.mosip.openID4VP.jwt.jwe.JWEHandler
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.testData.authorizationRequestForResponseModeJWT
import io.mosip.openID4VP.testData.authorizationResponse
import io.mosip.openID4VP.testData.clientMetadataString
import io.mosip.openID4VP.testData.walletConfig
import org.junit.Test
import kotlin.test.*

class DirectPostJwtResponseModeHandlerTest {

    @BeforeTest
    fun setUp() {
        mockkObject(NetworkManagerClient)
        mockkConstructor(JWEHandler::class)
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    /** validation of client metadata **/

    @Test
    fun `should validate the mandatory fields of clientMetadata`() {
        val clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataDraft23Serializer)
        DirectPostJwtResponseModeHandler().validate(clientMetadata, walletConfig, false)
    }

    @Test
    fun `should throw error if jwks field is missing in clientMetadata`() {
        val clientMetadataStr =
            """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_alg":"ECDH-ES","authorization_encrypted_response_enc":"A256GCM","vp_formats":{"ldp_vp":{"proof_type":["Ed25519Signature2018"]}}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataDraft23Serializer)

        val exception = assertFailsWith<MissingInput> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletConfig, false)
        }
        assertEquals("Missing Input: client_metadata->jwks param is required", exception.message)
    }

    @Test
    fun `should throw error if authorization_encrypted_response_enc field is missing in clientMetadata`() {
        val clientMetadataStr =
            """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_alg":"ECDH-ES","vp_formats":{"ldp_vp":{"proof_type":["Ed25519Signature2018"]}}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataDraft23Serializer)

        val exception = assertFailsWith<MissingInput> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletConfig, false)
        }
        assertEquals(
            "Missing Input: client_metadata->authorization_encrypted_response_enc param is required",
            exception.message
        )
    }

    @Test
    fun `should throw error if authorization_encrypted_response_alg field is missing in clientMetadata`() {
        val clientMetadataStr =
            """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_enc":"A256GCM","vp_formats":{"ldp_vp":{"proof_type":["Ed25519Signature2018"]}}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataDraft23Serializer)

        val exception = assertFailsWith<MissingInput> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletConfig, false)
        }
        assertEquals(
            "Missing Input: client_metadata->authorization_encrypted_response_alg param is required",
            exception.message
        )
    }

    @Test
    fun `should throw error if no jwk matching the key encryption algorithm is found`() {
        val clientMetadataStr =
            """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_alg":"ECDH-ES","authorization_encrypted_response_enc":"A256GCM","jwks":{"keys":[{"kty":"OKP","crv":"X25519","use":"enc","x":"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4","alg":"ECDH","kid":"ed-key1"}]},"vp_formats":{"mso_mdoc":{"alg":["ES256"]}}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataDraft23Serializer)

        val exception = assertFailsWith<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletConfig, false)
        }
        assertEquals(
            "No jwk matching the specified algorithm found for encryption",
            exception.message
        )
    }

    @Test
    fun `should validate clientMetadata when jwk use is not enc`() {
        val clientMetadataStr =
            """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_alg":"ECDH-ES","authorization_encrypted_response_enc":"A256GCM","jwks":{"keys":[{"kty":"OKP","crv":"X25519","use":"sign","x":"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4","alg":"ECDH-ES","kid":"ed-key1"}]},"vp_formats":{"mso_mdoc":{"alg":["ES256"]}}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataDraft23Serializer)

        DirectPostJwtResponseModeHandler().validate(clientMetadata, walletConfig, false)
    }

    @Test
    fun `should validate clientMetadata when jwk use is missing`() {
        val clientMetadataStr =
            """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_alg":"ECDH-ES","authorization_encrypted_response_enc":"A256GCM","jwks":{"keys":[{"kty":"OKP","crv":"X25519","x":"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4","alg":"ECDH-ES","kid":"ed-key1"}]},"vp_formats":{"mso_mdoc":{"alg":["ES256"]}}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataDraft23Serializer)

        DirectPostJwtResponseModeHandler().validate(clientMetadata, walletConfig, false)
    }

    @Test
    fun `should use enc only as tie breaker when multiple jwks match algorithm`() {
        val clientMetadataStr =
            """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_alg":"ECDH-ES","authorization_encrypted_response_enc":"A256GCM","jwks":{"keys":[{"kty":"OKP","crv":"X25519","use":"sig","x":"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4","alg":"ECDH-ES","kid":"sig-key"},{"kty":"OKP","crv":"X25519","use":"enc","x":"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4","alg":"ECDH-ES","kid":"enc-key"}]},"vp_formats":{"mso_mdoc":{"alg":["ES256"]}}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataDraft23Serializer)

        DirectPostJwtResponseModeHandler().validate(clientMetadata, walletConfig, false)
    }

    @Test
    fun `should throw error when multiple jwks match algorithm without single encryption key tie breaker`() {
        val clientMetadataStr =
            """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_alg":"ECDH-ES","authorization_encrypted_response_enc":"A256GCM","jwks":{"keys":[{"kty":"OKP","crv":"X25519","use":"sig","x":"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4","alg":"ECDH-ES","kid":"sig-key"},{"kty":"OKP","crv":"X25519","x":"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4","alg":"ECDH-ES","kid":"key-without-use"}]},"vp_formats":{"mso_mdoc":{"alg":["ES256"]}}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataDraft23Serializer)

        val exception = assertFailsWith<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletConfig, false)
        }
        assertEquals(
            "Multiple jwks matching the specified algorithm found for encryption",
            exception.message
        )
    }

    @Test
    fun `should validate the fields of clientMetadata with walletConfig`() {
        val clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataDraft23Serializer)
        DirectPostJwtResponseModeHandler().validate(clientMetadata, walletConfig, true)
    }

    @Test
    fun `should throw error if the key exchange algorithm does not match supported list from the walletConfig`() {
        val clientMetadataStr =
            """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_alg":"ECDH","authorization_encrypted_response_enc":"A256GCM","jwks":{"keys":[{"kty":"OKP","crv":"X25519","use":"enc","x":"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4","alg":"ECDH","kid":"ed-key1"}]},"vp_formats":{"mso_mdoc":{},"ldp_vc":{"proof_type":["Ed25519Signature2018","Ed25519Signature2020"]}}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataDraft23Serializer)

        val exception = assertFailsWith<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletConfig, true)
        }
        assertEquals("Authorization response encryption algorithm is not supported", exception.message)
    }


    @Test
    fun `should throw error if the encryption algorithm does not match supported list from the walletConfig`() {
        val clientMetadataStr =
            """{"client_name":"Requestername","logo_uri":"<logo_uri>","authorization_encrypted_response_alg":"ECDH-ES","authorization_encrypted_response_enc":"A256","jwks":{"keys":[{"kty":"OKP","crv":"X25519","use":"enc","x":"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4","alg":"ECDH-ES","kid":"ed-key1"}]},"vp_formats":{"mso_mdoc":{},"ldp_vc":{"proof_type":["Ed25519Signature2018","Ed25519Signature2020"]}}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataDraft23Serializer)

        val exception = assertFailsWith<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletConfig, true)
        }
        assertEquals("authorization_encrypted_response_enc is not supported", exception.message)
    }

    @Test
    fun `should throw error when clientMetadata Draft23 is null`() {
        val exception = assertFailsWith<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(null as io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataDraft23?, walletConfig, false)
        }
        assertEquals("client_metadata must be present for given response mode", exception.message)
    }

    /** validate(ClientMetadata?) - V1 overload **/

    @Test
    fun `should validate V1 clientMetadata successfully`() {
        val clientMetadataStr = """{"vp_formats_supported":{"ldp_vc":{"proof_type":["Ed25519Signature2018"]}},"encrypted_response_enc_values_supported":["A256GCM"],"jwks":{"keys":[{"kty":"OKP","crv":"X25519","use":"enc","x":"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4","alg":"ECDH-ES","kid":"enc-key1"}]}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)
        DirectPostJwtResponseModeHandler().validate(clientMetadata, walletConfig, false)
    }

    @Test
    fun `should throw error when V1 clientMetadata is null`() {
        val exception = assertFailsWith<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(null as io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata?, walletConfig, false)
        }
        assertEquals("client_metadata must be present for given response mode", exception.message)
    }

    @Test
    fun `should throw error when V1 clientMetadata has no encrypted_response_enc_values_supported`() {
        val clientMetadataStr = """{"vp_formats_supported":{"ldp_vc":{"proof_type":["Ed25519Signature2018"]}},"jwks":{"keys":[{"kty":"OKP","crv":"X25519","use":"enc","x":"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4","alg":"ECDH-ES","kid":"enc-key1"}]}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exception = assertFailsWith<MissingInput> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletConfig, false)
        }
        assertEquals("Missing Input: client_metadata->encrypted_response_enc_values_supported param is required", exception.message)
    }

    @Test
    fun `should throw error when V1 clientMetadata has empty encrypted_response_enc_values_supported`() {
        val clientMetadata = ClientMetadata(
            vpFormatsSupported = mapOf(
                FormatType.LDP_VC.value to LdpVpFormatSupported(
                    proofTypeValues = listOf(ProofType.Ed25519Signature2020)
                )
            ),
            encryptedResponseEncValuesSupported = emptyList(),
            jwks = Jwks(
                keys = listOf(
                    Jwk(
                        kty = "OKP",
                        crv = "X25519",
                        use = "enc",
                        x = "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                        alg = "ECDH-ES",
                        kid = "enc-key1"
                    )
                )
            )
        )

        val exception = assertFailsWith<MissingInput> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletConfig, false)
        }
        assertEquals("Missing Input: client_metadata->encrypted_response_enc_values_supported param is required", exception.message)
    }

    @Test
    fun `should throw error when V1 clientMetadata has no jwks`() {
        val clientMetadataStr = """{"vp_formats_supported":{"ldp_vc":{"proof_type":["Ed25519Signature2018"]}},"encrypted_response_enc_values_supported":["A256GCM"]}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exception = assertFailsWith<MissingInput> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletConfig, false)
        }
        assertEquals("Missing Input: client_metadata->jwks param is required", exception.message)
    }

    @Test
    fun `should throw error when V1 clientMetadata jwks keys have no alg field`() {
        val clientMetadataStr = """{"vp_formats_supported":{"ldp_vc":{"proof_type":["Ed25519Signature2018"]}},"encrypted_response_enc_values_supported":["A256GCM"],"jwks":{"keys":[{"kty":"OKP","alg": "ECDH-S","crv":"X25519","use":"enc","x":"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4","kid":"enc-key1"}]}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exception = assertFailsWith<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletConfig, false)
        }
        assertEquals("No jwk matching the specified algorithm found for encryption", exception.message)
    }

    data class SelectEncryptionKeyCase(val description: String, val jwksJson: String, val expectedError: String)

    @Test
    fun `should throw correct error for selectEncryptionKey edge cases in V1 validate`() {
        val cases = listOf(
            SelectEncryptionKeyCase(
                description = "no jwk matching wallet supported algorithm",
                jwksJson = """[{"kty":"OKP","crv":"X25519","use":"enc","x":"BVNVdq","alg":"RSA-OAEP","kid":"key1"}]""",
                expectedError = "No jwk matching the specified algorithm found for encryption"
            ),
            SelectEncryptionKeyCase(
                description = "multiple jwks matching algorithm without single enc key",
                jwksJson = """[{"kty":"OKP","crv":"X25519","use":"sig","x":"BVNVdq","alg":"ECDH-ES","kid":"key1"},{"kty":"OKP","crv":"X25519","x":"BVNVdq","alg":"ECDH-ES","kid":"key2"}]""",
                expectedError = "Multiple jwks matching the specified algorithm found for encryption"
            )
        )

        cases.forEach { case ->
            val clientMetadataStr = """{"vp_formats_supported":{"ldp_vc":{"proof_type":["Ed25519Signature2018"]}},"encrypted_response_enc_values_supported":["A256GCM"],"jwks":{"keys":${case.jwksJson}}}"""
            val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

            val exception = assertFailsWith<InvalidData>(message = "Failed for case: ${case.description}") {
                DirectPostJwtResponseModeHandler().validate(clientMetadata, walletConfig, false)
            }
            assertEquals(case.expectedError, exception.message, "Unexpected error for: ${case.description}")
        }
    }

    @Test
    fun `should throw error when V1 clientMetadata alg not in wallet supported algorithms`() {
        val clientMetadataStr = """{"vp_formats_supported":{"ldp_vc":{"proof_type":["Ed25519Signature2018"]}},"encrypted_response_enc_values_supported":["A256GCM"],"jwks":{"keys":[{"kty":"OKP","crv":"X25519","use":"enc","x":"BVNVdq","alg":"RSA-OAEP","kid":"key1"}]}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exception = assertFailsWith<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletConfig, true)
        }
        assertEquals("Authorization response encryption algorithm is not supported", exception.message)
    }

    @Test
    fun `should throw error when V1 clientMetadata enc not in wallet supported enc values`() {
        val clientMetadataStr = """{"vp_formats_supported":{"ldp_vc":{"proof_type":["Ed25519Signature2018"]}},"encrypted_response_enc_values_supported":["A128GCM"],"jwks":{"keys":[{"kty":"OKP","crv":"X25519","use":"enc","x":"BVNVdq","alg":"ECDH-ES","kid":"key1"}]}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exception = assertFailsWith<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletConfig, true)
        }
        assertEquals("authorization_encrypted_response_enc is not supported", exception.message)
    }

    @Test
    fun `should throw error when wallet metadata misses encryption alg values and validation is enabled`() {
        val clientMetadataStr = """{"vp_formats_supported":{"ldp_vc":{"proof_type":["Ed25519Signature2018"]}},"encrypted_response_enc_values_supported":["A256GCM"],"jwks":{"keys":[{"kty":"OKP","crv":"X25519","use":"enc","x":"BVNVdq","alg":"ECDH-ES","kid":"key1"}]}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)
        val walletConfigWithoutAlgSupport = WalletConfig(
            authorizationEncryptionAlgValuesSupported = null,
            authorizationEncryptionEncValuesSupported = walletConfig.authorizationEncryptionEncValuesSupported,
            vpFormatsSupported = walletConfig.vpFormatsSupported,
            clientIdPrefixesSupported = walletConfig.clientIdPrefixesSupported,
            requestObjectSigningAlgValuesSupported = walletConfig.requestObjectSigningAlgValuesSupported,
            responseTypesSupported = walletConfig.responseTypesSupported,
            isPresentationDefinitionUriSupported = walletConfig.isPresentationDefinitionUriSupported,
            trustedVerifiers = walletConfig.trustedVerifiers,
            validateTrustedVerifier = walletConfig.validateTrustedVerifier
        )

        val exception = assertFailsWith<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletConfigWithoutAlgSupport, true)
        }
        assertEquals("authorization_encryption_alg_values_supported must be present in wallet_metadata", exception.message)
    }

    @Test
    fun `should throw error when wallet metadata misses encryption enc values and validation is enabled`() {
        val clientMetadataStr = """{"vp_formats_supported":{"ldp_vc":{"proof_type":["Ed25519Signature2018"]}},"encrypted_response_enc_values_supported":["A256GCM"],"jwks":{"keys":[{"kty":"OKP","crv":"X25519","use":"enc","x":"BVNVdq","alg":"ECDH-ES","kid":"key1"}]}}"""
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)
        val walletConfigWithoutEncSupport = WalletConfig(
            authorizationEncryptionAlgValuesSupported = walletConfig.authorizationEncryptionAlgValuesSupported,
            authorizationEncryptionEncValuesSupported = null,
            vpFormatsSupported = walletConfig.vpFormatsSupported,
            clientIdPrefixesSupported = walletConfig.clientIdPrefixesSupported,
            requestObjectSigningAlgValuesSupported = walletConfig.requestObjectSigningAlgValuesSupported,
            responseTypesSupported = walletConfig.responseTypesSupported,
            isPresentationDefinitionUriSupported = walletConfig.isPresentationDefinitionUriSupported,
            trustedVerifiers = walletConfig.trustedVerifiers,
            validateTrustedVerifier = walletConfig.validateTrustedVerifier
        )

        val exception = assertFailsWith<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletConfigWithoutEncSupport, true)
        }
        assertEquals("authorization_encryption_enc_values_supported must be present in wallet_metadata", exception.message)
    }

    /** sending of authorization response **/

    @Test
    fun `should send the authorization response with JWE in requestBody successfully`() {
        val responseUri = "https://mock-verifier.com/response"
        val vpShareSuccessResponse = "VP shared successfully"

        every {
            NetworkManagerClient.sendHTTPRequest(
                responseUri,
                HttpMethod.POST,
                any(),
                any()
            )
        } returns NetworkResponse(200, vpShareSuccessResponse, emptyMap())

        every { anyConstructed<JWEHandler>().generateEncryptedResponse(any()) } returns "eytyiewr.....jewjr"

        val actualResponse = DirectPostJwtResponseModeHandler().sendAuthorizationResponse(
            authorizationRequestForResponseModeJWT,
            responseUri,
            authorizationResponse,
            "walletNonce",
            walletConfig = walletConfig
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                url = responseUri,
                method = HttpMethod.POST,
                bodyParams = mapOf("response" to "eytyiewr.....jewjr"),
                headers = mapOf("Content-Type" to ContentType.APPLICATION_FORM_URL_ENCODED.value)
            )
        }
        assertEquals(vpShareSuccessResponse, actualResponse.body)
    }

    /** getAuthorizationResponse tests **/

    @Test
    fun `getAuthorizationResponse should encrypt AuthorizationResponse successfully`() {
        val walletNonce = "test-wallet-nonce"
        val expectedEncryptedResponse =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.encrypted_payload.signature"

        every { anyConstructed<JWEHandler>().generateEncryptedResponse(any()) } returns expectedEncryptedResponse

        val result = DirectPostJwtResponseModeHandler().getAuthorizationResponse(
            authorizationRequestForResponseModeJWT,
            authorizationResponse,
            walletNonce,
            walletConfig
        )

        assertEquals(mapOf("response" to expectedEncryptedResponse), result)

        verify {
            anyConstructed<JWEHandler>().generateEncryptedResponse(any())
        }
    }

    @Test
    fun `getAuthorizationResponse should use correct JWE configuration for AuthorizationResponse`() {
        val walletNonce = "wallet-nonce-123"
        val expectedEncryptedResponse = "encrypted.jwt.token"

        every { anyConstructed<JWEHandler>().generateEncryptedResponse(any()) } returns expectedEncryptedResponse

        val result = DirectPostJwtResponseModeHandler().getAuthorizationResponse(
            authorizationRequestForResponseModeJWT,
            authorizationResponse,
            walletNonce,
            walletConfig
        )

        verify {
            anyConstructed<JWEHandler>().generateEncryptedResponse(any())
        }

        assertEquals(mapOf("response" to expectedEncryptedResponse), result)
    }

    @Test
    fun `getAuthorizationErrorResponse should not encrypt AuthorizationErrorResponse successfully`() {
        val walletNonce = "error-wallet-nonce"
        val errorResponse = AuthorizationErrorResponse(
            error = "invalid_request",
            errorDescription = "Test error description",
            state = "test-state"
        )

        val result = DirectPostJwtResponseModeHandler().getAuthorizationErrorResponse(
            authorizationRequestForResponseModeJWT,
            errorResponse,
            walletNonce
        )

        assertEquals(
            mapOf(
                "error" to "invalid_request",
                "error_description" to "Test error description",
                "state" to "test-state"
            ), result
        )
    }

    @Test
    fun `getAuthorizationResponse should find correct encryption key from jwks`() {
        val walletNonce = "jwk-test-nonce"
        val expectedEncryptedResponse = "jwk.encrypted.response"

        every { anyConstructed<JWEHandler>().generateEncryptedResponse(any()) } returns expectedEncryptedResponse

        val result = DirectPostJwtResponseModeHandler().getAuthorizationResponse(
            authorizationRequestForResponseModeJWT,
            authorizationResponse,
            walletNonce,
            walletConfig
        )

        verify {
            anyConstructed<JWEHandler>().generateEncryptedResponse(any())
        }
        assertEquals(mapOf("response" to expectedEncryptedResponse), result)
    }

    @Test
    fun `getAuthorizationResponse should pass response params to JWE encryption for AuthorizationResponse`() {
        val walletNonce = "params-test-nonce"
        val expectedEncryptedResponse = "params.encrypted.response"

        every { anyConstructed<JWEHandler>().generateEncryptedResponse(any()) } returns expectedEncryptedResponse

        DirectPostJwtResponseModeHandler().getAuthorizationResponse(
            authorizationRequestForResponseModeJWT,
            authorizationResponse,
            walletNonce,
            walletConfig
        )

        verify {
            anyConstructed<JWEHandler>().generateEncryptedResponse(
                match { params ->
                    params.isNotEmpty() &&
                            params.containsKey("vp_token") &&
                            params.containsKey("presentation_submission")
                }
            )
        }
    }

    @Test
    fun `getAuthorizationErrorResponse should handle AuthorizationErrorResponse with null state`() {
        val walletNonce = "null-state-nonce"
        val errorResponse = AuthorizationErrorResponse(
            error = "invalid_grant",
            errorDescription = "Invalid grant provided",
            state = null
        )

        val result = DirectPostJwtResponseModeHandler().getAuthorizationErrorResponse(
            authorizationRequestForResponseModeJWT,
            errorResponse,
            walletNonce
        )

        assertEquals(mapOf(
            "error" to "invalid_grant",
            "error_description" to "Invalid grant provided",
        ), result)
    }

    @Test
    fun `getAuthorizationResponse should return map with response key`() {
        val walletNonce = "response-key-nonce"
        val encryptedContent = "response.key.test.encrypted"

        every { anyConstructed<JWEHandler>().generateEncryptedResponse(any()) } returns encryptedContent

        val result = DirectPostJwtResponseModeHandler().getAuthorizationResponse(
            authorizationRequestForResponseModeJWT,
            authorizationResponse,
            walletNonce,
            walletConfig
        )

        assertEquals(1, result.size)
        assertEquals(encryptedContent, result["response"])
        assertTrue(result.containsKey("response"))
    }

    @Test
    fun `getVerifierPublicKeyForEncryption should return Draft23 encryption key`() {
        val key = DirectPostJwtResponseModeHandler().getVerifierPublicKeyForEncryption(
            authorizationRequestForResponseModeJWT,
            walletConfig
        )

        assertNotNull(key)
        assertEquals("ECDH-ES", key.alg)
        assertEquals("enc-key1", key.kid)
    }

    @Test
    fun `getVerifierPublicKeyForEncryption should return V1 encryption key`() {
        val request = createV1AuthorizationRequest(
            clientMetadata = ClientMetadata(
                vpFormatsSupported = mapOf(
                    FormatType.LDP_VC.value to LdpVpFormatSupported(
                        proofTypeValues = listOf(ProofType.Ed25519Signature2020)
                    )
                ),
                encryptedResponseEncValuesSupported = listOf("A256GCM"),
                jwks = Jwks(
                    keys = listOf(
                        Jwk(
                            kty = "OKP",
                            crv = "X25519",
                            use = "enc",
                            x = "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                            alg = "ECDH-ES",
                            kid = "enc-key-v1"
                        )
                    )
                )
            )
        )

        val key = DirectPostJwtResponseModeHandler().getVerifierPublicKeyForEncryption(request, walletConfig)
        assertNotNull(key)
        assertEquals("enc-key-v1", key.kid)
    }

    @Test
    fun `getAuthorizationResponse should encrypt response for V1 authorization request`() {
        val request = createV1AuthorizationRequest(
            clientMetadata = ClientMetadata(
                vpFormatsSupported = mapOf(
                    FormatType.LDP_VC.value to LdpVpFormatSupported(
                        proofTypeValues = listOf(ProofType.Ed25519Signature2020)
                    )
                ),
                encryptedResponseEncValuesSupported = listOf("A256GCM"),
                jwks = Jwks(
                    keys = listOf(
                        Jwk(
                            kty = "OKP",
                            crv = "X25519",
                            use = "enc",
                            x = "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                            alg = "ECDH-ES",
                            kid = "enc-key-v1"
                        )
                    )
                )
            )
        )

        every { anyConstructed<JWEHandler>().generateEncryptedResponse(any()) } returns "v1.encrypted.response"

        val result = DirectPostJwtResponseModeHandler().getAuthorizationResponse(
            request,
            authorizationResponse,
            "wallet-nonce-v1",
            walletConfig
        )

        assertEquals(mapOf("response" to "v1.encrypted.response"), result)
        verify { anyConstructed<JWEHandler>().generateEncryptedResponse(any()) }
    }

    private fun createV1AuthorizationRequest(clientMetadata: ClientMetadata?): AuthorizationDcqlRequest {
        return AuthorizationDcqlRequest(
            clientId = "v1-client",
            responseType = "vp_token",
            responseMode = "direct_post.jwt",
            responseUri = "https://mock-verifier.com/response",
            redirectUri = null,
            nonce = "test-nonce-v1",
            walletNonce = null,
            state = null,
            clientMetadata = clientMetadata,
            dcqlQuery = DCQLQuery(
                credentials = listOf(
                    CredentialQuery(
                        id = "cred-query-1",
                        format = FormatType.LDP_VC.value
                    )
                )
            )
        )
    }

    /** Tests for ResponseDispatchInfo-based methods **/

    @Test
    fun `getAuthorizationErrorResponse with ResponseDispatchInfo should return encrypted JWT`() {
        val handler = DirectPostJwtResponseModeHandler()
        
        val mockJwk = Jwk(
            kty = "EC",
            crv = "P-256",
            x = "test-x",
            y = "test-y",
            alg = "ECDH-ES"
        )
        
        val encryptionSpec = io.mosip.openID4VP.responseModeHandler.ResponseEncryptionSpecification(
            keyEncryptionAlg = "ECDH-ES",
            contentEncryptionAlg = "A256GCM",
            verifierPublicKey = mockJwk
        )
        
        val dispatchInfo = io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo(
            responseMode = "direct_post.jwt",
            nonce = "test-nonce",
            state = "test-state",
            clientId = "test-client",
            responseEncryptionSpecification = encryptionSpec
        )

        every { 
            anyConstructed<JWEHandler>().generateEncryptedResponse(any()) 
        } returns "encrypted-jwt-token"

        val result = handler.getAuthorizationErrorResponse(
            dispatchInfo = dispatchInfo,
            error = "access_denied",
            errorDescription = "User rejected the consent"
        )

        assertEquals(1, result.size)
        assertTrue(result.containsKey("response"))
        assertEquals("encrypted-jwt-token", result["response"])
        
        verify {
            anyConstructed<JWEHandler>().generateEncryptedResponse(
                match { 
                    it["error"] == "access_denied" && 
                    it["error_description"] == "User rejected the consent" &&
                    it["state"] == "test-state"
                }
            )
        }
    }

    @Test
    fun `getAuthorizationErrorResponse with ResponseDispatchInfo without encryption should return plain map`() {
        val handler = DirectPostJwtResponseModeHandler()
        
        val dispatchInfo = io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo(
            responseMode = "direct_post.jwt",
            nonce = "test-nonce",
            state = "test-state",
            clientId = "test-client",
            responseEncryptionSpecification = null
        )

        val result = handler.getAuthorizationErrorResponse(
            dispatchInfo = dispatchInfo,
            error = "invalid_request",
            errorDescription = "Missing required parameter"
        )

        assertEquals(3, result.size)
        assertEquals("invalid_request", result["error"])
        assertEquals("Missing required parameter", result["error_description"])
        assertEquals("test-state", result["state"])
    }

    @Test
    fun `getAuthorizationErrorResponse with ResponseDispatchInfo should include state and nonce`() {
        val handler = DirectPostJwtResponseModeHandler()
        
        val mockJwk = Jwk(
            kty = "EC",
            crv = "P-256",
            x = "test-x",
            y = "test-y",
            alg = "ECDH-ES"
        )
        
        val encryptionSpec = io.mosip.openID4VP.responseModeHandler.ResponseEncryptionSpecification(
            keyEncryptionAlg = "ECDH-ES",
            contentEncryptionAlg = "A256GCM",
            verifierPublicKey = mockJwk
        )
        
        val dispatchInfo = io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo(
            responseMode = "direct_post.jwt",
            nonce = "verifier-nonce-123",
            state = "state-abc",
            clientId = "test-client",
            responseEncryptionSpecification = encryptionSpec
        )

        every { 
            anyConstructed<JWEHandler>().generateEncryptedResponse(any()) 
        } returns "encrypted-jwt"

        val result = handler.getAuthorizationErrorResponse(
            dispatchInfo = dispatchInfo,
            error = "access_denied",
            errorDescription = null
        )

        assertEquals(1, result.size)
        assertTrue(result.containsKey("response"))
        assertEquals("encrypted-jwt", result["response"])
    }

    @Test
    fun `getAuthorizationErrorResponse with ResponseDispatchInfo should handle null optional fields`() {
        val handler = DirectPostJwtResponseModeHandler()
        
        val dispatchInfo = io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo(
            responseMode = "direct_post.jwt",
            nonce = null,
            state = null,
            clientId = "test-client",
            responseEncryptionSpecification = null
        )

        val result = handler.getAuthorizationErrorResponse(
            dispatchInfo = dispatchInfo,
            error = "invalid_scope",
            errorDescription = null
        )

        assertEquals(1, result.size)
        assertEquals("invalid_scope", result["error"])
        assertFalse(result.containsKey("error_description"))
        assertFalse(result.containsKey("state"))
    }

    @Test
    fun `sendAuthorizationError with ResponseDispatchInfo should post to responseUri`() {
        val handler = DirectPostJwtResponseModeHandler()
        
        val mockJwk = Jwk(
            kty = "EC",
            crv = "P-256",
            x = "test-x",
            y = "test-y",
            alg = "ECDH-ES"
        )
        
        val encryptionSpec = io.mosip.openID4VP.responseModeHandler.ResponseEncryptionSpecification(
            keyEncryptionAlg = "ECDH-ES",
            contentEncryptionAlg = "A256GCM",
            verifierPublicKey = mockJwk
        )
        
        val dispatchInfo = io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo(
            responseMode = "direct_post.jwt",
            nonce = "test-nonce",
            state = "test-state",
            clientId = "test-client",
            responseEncryptionSpecification = encryptionSpec
        )

        val mockNetworkResponse = NetworkResponse(
            statusCode = 200,
            body = """{"status":"ok"}""",
            headers = emptyMap()
        )

        every { 
            anyConstructed<JWEHandler>().generateEncryptedResponse(any()) 
        } returns "encrypted-jwt-error"

        every {
            NetworkManagerClient.sendHTTPRequest(
                url = "https://verifier.example.com/callback",
                method = HttpMethod.POST,
                bodyParams = any(),
                headers = any()
            )
        } returns mockNetworkResponse

        val result = handler.sendAuthorizationError(
            dispatchInfo = dispatchInfo,
            error = "access_denied",
            errorDescription = "User declined",
            responseUri = "https://verifier.example.com/callback"
        )

        assertEquals(200, result.statusCode)
        verify {
            NetworkManagerClient.sendHTTPRequest(
                url = "https://verifier.example.com/callback",
                method = HttpMethod.POST,
                bodyParams = match { it["response"] == "encrypted-jwt-error" },
                headers = match { it["Content-Type"] == ContentType.APPLICATION_FORM_URL_ENCODED.value }
            )
        }
    }

    @Test
    fun `getAuthorizationResponse with ResponseDispatchInfo should return encrypted JWT`() {
        val handler = DirectPostJwtResponseModeHandler()
        
        val mockJwk = Jwk(
            kty = "EC",
            crv = "P-256",
            x = "test-x",
            y = "test-y",
            alg = "ECDH-ES"
        )
        
        val encryptionSpec = io.mosip.openID4VP.responseModeHandler.ResponseEncryptionSpecification(
            keyEncryptionAlg = "ECDH-ES",
            contentEncryptionAlg = "A256GCM",
            verifierPublicKey = mockJwk
        )
        
        val dispatchInfo = io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo(
            responseMode = "direct_post.jwt",
            nonce = "verifier-nonce",
            state = "request-state",
            clientId = "test-client",
            responseEncryptionSpecification = encryptionSpec
        )

        every { 
            anyConstructed<JWEHandler>().generateEncryptedResponse(any()) 
        } returns "encrypted-success-jwt"

        val result = handler.getAuthorizationResponse(
            dispatchInfo = dispatchInfo,
            vpToken = "vp-token-value",
            presentationSubmission = """{"descriptor_map":[]}""",
            walletNonce = "wallet-nonce-123"
        )

        assertEquals(1, result.size)
        assertTrue(result.containsKey("response"))
        assertEquals("encrypted-success-jwt", result["response"])
    }

    @Test
    fun `getAuthorizationResponse with ResponseDispatchInfo should throw exception without encryption spec`() {
        val handler = DirectPostJwtResponseModeHandler()
        
        val dispatchInfo = io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo(
            responseMode = "direct_post.jwt",
            nonce = "test-nonce",
            state = "test-state",
            clientId = "test-client",
            responseEncryptionSpecification = null
        )

        assertFailsWith<InvalidData> {
            handler.getAuthorizationResponse(
                dispatchInfo = dispatchInfo,
                vpToken = "vp-token",
                presentationSubmission = null,
                walletNonce = "wallet-nonce"
            )
        }
    }

    @Test
    fun `sendAuthorizationResponse with ResponseDispatchInfo should post to responseUri`() {
        val handler = DirectPostJwtResponseModeHandler()
        
        val mockJwk = Jwk(
            kty = "EC",
            crv = "P-256",
            x = "test-x",
            y = "test-y",
            alg = "ECDH-ES"
        )
        
        val encryptionSpec = io.mosip.openID4VP.responseModeHandler.ResponseEncryptionSpecification(
            keyEncryptionAlg = "ECDH-ES",
            contentEncryptionAlg = "A256GCM",
            verifierPublicKey = mockJwk
        )
        
        val dispatchInfo = io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo(
            responseMode = "direct_post.jwt",
            nonce = "test-nonce",
            state = "test-state",
            clientId = "test-client",
            responseEncryptionSpecification = encryptionSpec
        )

        val mockNetworkResponse = NetworkResponse(
            statusCode = 200,
            body = """{"redirect_uri":"https://wallet.example.com/success"}""",
            headers = emptyMap()
        )

        every { 
            anyConstructed<JWEHandler>().generateEncryptedResponse(any()) 
        } returns "encrypted-success-response"

        every {
            NetworkManagerClient.sendHTTPRequest(
                url = "https://verifier.example.com/response",
                method = HttpMethod.POST,
                bodyParams = any(),
                headers = any()
            )
        } returns mockNetworkResponse

        val result = handler.sendAuthorizationResponse(
            dispatchInfo = dispatchInfo,
            vpToken = "vp-token-data",
            presentationSubmission = """{"id":"submission-1"}""",
            walletNonce = "wallet-nonce-xyz",
            responseUri = "https://verifier.example.com/response"
        )

        assertEquals(200, result.statusCode)
        verify {
            NetworkManagerClient.sendHTTPRequest(
                url = "https://verifier.example.com/response",
                method = HttpMethod.POST,
                bodyParams = match { it["response"] == "encrypted-success-response" },
                headers = match { it["Content-Type"] == ContentType.APPLICATION_FORM_URL_ENCODED.value }
            )
        }
    }

    @Test
    fun `getAuthorizationErrorResponse should support different error types`() {
        val handler = DirectPostJwtResponseModeHandler()
        
        val dispatchInfo = io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo(
            responseMode = "direct_post.jwt",
            nonce = null,
            state = null,
            clientId = "test-client",
            responseEncryptionSpecification = null
        )

        val errorTypes = listOf(
            "access_denied" to "User rejected",
            "invalid_request" to "Missing parameter",
            "invalid_scope" to "Unsupported scope",
            "server_error" to "Internal error"
        )

        errorTypes.forEach { (error, description) ->
            val result = handler.getAuthorizationErrorResponse(
                dispatchInfo = dispatchInfo,
                error = error,
                errorDescription = description
            )

            assertEquals(error, result["error"])
            assertEquals(description, result["error_description"])
        }
    }
}
