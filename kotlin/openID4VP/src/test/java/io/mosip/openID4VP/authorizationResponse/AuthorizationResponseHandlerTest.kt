package io.mosip.openID4VP.authorizationResponse

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.verify
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PathNested
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.VPTokenSigningPayload
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPTokenBuilder
import io.mosip.openID4VP.common.DateUtil
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.exceptions.Exceptions
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.jwt.jwe.JWEHandler
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandler
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory
import io.mosip.openID4VP.testData.authorizationRequest
import io.mosip.openID4VP.testData.authorizationRequestForResponseModeJWT
import io.mosip.openID4VP.testData.clientMetadataMap
import io.mosip.openID4VP.testData.holderId
import io.mosip.openID4VP.testData.presentationDefinitionMap
import io.mosip.openID4VP.testData.setField
import io.mosip.openID4VP.testData.ldpvpTokenSigningResults
import io.mosip.openID4VP.testData.ldpCredential1
import io.mosip.openID4VP.testData.ldpCredential2
import io.mosip.openID4VP.testData.ldpVPToken
import io.mosip.openID4VP.testData.ldpVPTokenSigningResult
import io.mosip.openID4VP.testData.mdocvpTokenSigningResults
import io.mosip.openID4VP.testData.mdocCredential
import io.mosip.openID4VP.testData.mdocVPToken
import io.mosip.openID4VP.testData.mdocVPTokenSigningResult
import io.mosip.openID4VP.testData.proof
import io.mosip.openID4VP.testData.responseUrl
import io.mosip.openID4VP.testData.signatureSuite
import io.mosip.openID4VP.testData.unsignedLdpVPToken
import io.mosip.openID4VP.testData.unsignedMdocVPToken
import io.mosip.openID4VP.testData.unsignedVPTokens
import io.mosip.openID4VP.testData.vpTokenSigningPayload
import org.junit.After
import org.junit.Assert
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Ignore
import org.junit.Test
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.BeforeEach
import java.io.IOException

class AuthorizationResponseHandlerTest {
    private val ldpVcList1 = listOf(
        ldpCredential1,
        ldpCredential2
    )
    private val ldpVcList2 = listOf(
        ldpCredential2
    )
    private val mdocVcList = listOf(mdocCredential)
    private val selectedLdpVcCredentialsList = mapOf(
        "456" to mapOf(
            FormatType.LDP_VC to ldpVcList1
        ), "789" to mapOf(
            FormatType.LDP_VC to ldpVcList2
        )
    )
    private val selectedMdocCredentialsList = mapOf(
        "123" to mapOf(
            FormatType.MSO_MDOC to mdocVcList
        )
    )

    private val credentialsMap = mapOf(
        "input1" to mapOf(FormatType.LDP_VC to listOf(ldpCredential1)),
        "input2" to mapOf(FormatType.MSO_MDOC to listOf(mdocCredential))
    )

    private lateinit var authorizationResponseHandler: AuthorizationResponseHandler
    private val mockResponseHandler = mockk<ResponseModeBasedHandler>()

    @Before
    fun setUp() {
        authorizationResponseHandler = AuthorizationResponseHandler()

        mockkConstructor(LdpVPTokenBuilder::class)
        every { anyConstructed<LdpVPTokenBuilder>().build() } returns ldpVPToken

        mockkConstructor(MdocVPTokenBuilder::class)
        every { anyConstructed<MdocVPTokenBuilder>().build() } returns mdocVPToken

        setField(authorizationResponseHandler, "credentialsMap", selectedLdpVcCredentialsList + selectedMdocCredentialsList)
        setField(authorizationResponseHandler, "unsignedVPTokens", unsignedVPTokens)

        mockkStatic(Log::class)
        every { Log.e(any(), any()) } answers {
            val tag = arg<String>(0)
            val msg = arg<String>(1)
            println("Error: logTag: $tag | Message: $msg")
            0
        }

        mockkObject(UUIDGenerator)
        every { UUIDGenerator.generateUUID() } returns "649d581c-f291-4969-9cd5-2c27385a348f"

        mockkObject(DateUtil)
        every { DateUtil.formattedCurrentDateTime() } returns "2024-02-13T10:00:00Z"

        mockkObject(NetworkManagerClient)

        mockkConstructor(UnsignedLdpVPTokenBuilder::class)
        every { anyConstructed<UnsignedLdpVPTokenBuilder>().build() } returns mapOf(
            "unsignedVPToken" to unsignedLdpVPToken,
            "vpTokenSigningPayload" to vpTokenSigningPayload
        )

        mockkConstructor(UnsignedMdocVPTokenBuilder::class)
        every { anyConstructed<UnsignedMdocVPTokenBuilder>().build() } returns mapOf(
            "unsignedVPToken" to unsignedMdocVPToken,
            "vpTokenSigningPayload" to listOf(mdocCredential)
        )

        mockkObject(ResponseModeBasedHandlerFactory)

        every { ResponseModeBasedHandlerFactory.get(any()) } returns mockResponseHandler
        every { mockResponseHandler.sendAuthorizationResponse(any(), any(), any(), any()) } returns "success"

    }

    @After
    fun tearDown() {
        clearAllMocks()
    }

//    construction of vpTokens for signing

    @Test
    fun `should successfully construct unsigned VP tokens for both LDP_VC and MSO_MDOC formats`() {

        mockkConstructor(UnsignedLdpVPTokenBuilder::class)
        every { anyConstructed<UnsignedLdpVPTokenBuilder>().build() } returns mapOf("unsignedVPToken" to unsignedLdpVPToken, "vpTokenSigningPayload" to vpTokenSigningPayload)

        mockkConstructor(UnsignedMdocVPTokenBuilder::class)
        every { anyConstructed<UnsignedMdocVPTokenBuilder>().build() } returns mapOf("unsignedVPToken" to unsignedMdocVPToken, "vpTokenSigningPayload" to listOf(mdocCredential))

        val expectedUnsignedVPToken = mapOf(
            FormatType.LDP_VC to unsignedLdpVPToken,
            FormatType.MSO_MDOC to unsignedMdocVPToken
        )

        val unsignedVPToken = authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap =   selectedMdocCredentialsList+selectedLdpVcCredentialsList,
            authorizationRequest = authorizationRequest,
            responseUri = "https://mock-verifier.com",
            holderId = holderId,
            signatureSuite = signatureSuite
        )

        assertNotNull(unsignedVPToken)
        assertEquals(2, unsignedVPToken.size)
        assertEquals(expectedUnsignedVPToken[FormatType.LDP_VC], unsignedVPToken[FormatType.LDP_VC])
        assertEquals(expectedUnsignedVPToken[FormatType.MSO_MDOC], unsignedVPToken[FormatType.MSO_MDOC])
    }


    @Test
    fun `should throw error during construction of data for signing when selected Credentials is empty`() {
        val actualException =
            assertThrows(Exceptions.InvalidData::class.java) {
                authorizationResponseHandler.constructUnsignedVPToken(
                    credentialsMap = mapOf(),
                    authorizationRequest = authorizationRequest,
                    responseUri = "https://mock-verifier.com",
                    holderId = holderId,
                    signatureSuite = signatureSuite
                )
            }

        Assert.assertEquals(
            "Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request.",
            actualException.message
        )
    }

    // Sharing of Verifiable Presentation

    @Ignore
    @Test
    fun `should make network call to verifier responseUri with the vp_token, presentation_submission and state successfully`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com",
                HttpMethod.POST,
                any(),
                any()
            )
        } returns mapOf("body" to "VP share success")
        val authorizationResponse = AuthorizationResponse(
            presentationSubmission = PresentationSubmission(
                id = "649d581c-f291-4969-9cd5-2c27385a348f",
                definitionId = "649d581c-f891-4969-9cd5-2c27385a348f",
                descriptorMap = listOf(
                    DescriptorMap(
                        id = "456",
                        format = "ldp_vp",
                        path = "$",
                        pathNested = PathNested(
                            id = "456",
                            format = "ldp_vc",
                            path = "$.VerifiableCredential[0]"
                        )
                    ),
                    DescriptorMap(
                        id = "456",
                        format = "ldp_vp",
                        path = "$",
                        pathNested = PathNested(
                            id = "456",
                            format = "ldp_vc",
                            path = "$.VerifiableCredential[1]"
                        )
                    ),
                    DescriptorMap(
                        id = "789",
                        format = "ldp_vp",
                        path = "$",
                        pathNested = PathNested(
                            id = "789",
                            format = "ldp_vc",
                            path = "$.VerifiableCredential[2]"
                        )
                    )
                )
            ),
            vpToken = VPTokenType.VPTokenElement(
                value = LdpVPToken(
                    context = listOf("https://www.w3.org/2018/credentials/v1"),
                    type = listOf("VerifiablePresentation"),
                    verifiableCredential = listOf("credential1", "credential2", "credential3"),
                    id = "649d581c-f291-4969-9cd5-2c27385a348f",
                    holder = "",
                    proof = proof
                )
            ),
            state = "fsnC8ixCs6mWyV+00k23Qg=="
        )
        val expectedHeaders = mapOf("Content-Type" to "application/x-www-form-urlencoded")

        authorizationResponseHandler.shareVP(
            authorizationRequest = authorizationRequest,
            vpTokenSigningResults = ldpvpTokenSigningResults,
            responseUri = authorizationRequest.responseUri!!
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                url = authorizationRequest.responseUri!!,
                method = HttpMethod.POST,
                bodyParams = authorizationResponse.toJsonEncodedMap(),
                headers = expectedHeaders
            )
        }
    }

    @Ignore
    @Test
    fun `should make network call to verifier responseUri with encrypted body successfully when both mdoc vc is being shared`() {
        authorizationResponseHandler = AuthorizationResponseHandler()
//
//        mockkConstructor(LdpVPTokenBuilder::class)
//        every { anyConstructed<LdpVPTokenBuilder>().build() } returns ldpVPToken
//
//        mockkConstructor(MdocVPTokenBuilder::class)
//        every { anyConstructed<MdocVPTokenBuilder>().build() } returns mdocVPToken


        setField(authorizationResponseHandler, "credentialsMap", selectedLdpVcCredentialsList + selectedMdocCredentialsList)
        setField(authorizationResponseHandler, "unsignedVPTokens", unsignedVPTokens)

        every {
            NetworkManagerClient.sendHTTPRequest(
                authorizationRequestForResponseModeJWT.responseUri!!,
                HttpMethod.POST,
                any(),
                any()
            )
        } returns mapOf("body" to "VP share success")

        mockkConstructor(JWEHandler::class)
        every { anyConstructed<JWEHandler>().generateEncryptedResponse(any()) } returns "eytyiewr.....jewjr"
        val expectedBodyWithAuthResponseParams = mapOf(
            "response" to "eytyiewr.....jewjr"
        )
        val expectedHeaders = mapOf("Content-Type" to "application/x-www-form-urlencoded")

        authorizationResponseHandler.shareVP(
            authorizationRequest = authorizationRequestForResponseModeJWT,
            vpTokenSigningResults = ldpvpTokenSigningResults + mdocvpTokenSigningResults,
            responseUri = authorizationRequestForResponseModeJWT.responseUri!!
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                url = authorizationRequestForResponseModeJWT.responseUri!!,
                method = HttpMethod.POST,
                bodyParams = expectedBodyWithAuthResponseParams,
                headers = expectedHeaders
            )
        }
    }

    @Ignore
    @Test
    fun `should make network call to verifier responseUri with the vp_token, presentation_submission successfully`() {
        val authorizationRequestWithoutStateProperty = AuthorizationRequest(
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
            state = null,
            clientMetadata = deserializeAndValidate(clientMetadataMap, ClientMetadataSerializer)
        )
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com",
                HttpMethod.POST,
                any(),
                any()
            )
        } returns mapOf("body" to "VP share success")
        val expectedHeaders = mapOf("Content-Type" to "application/x-www-form-urlencoded")

        authorizationResponseHandler.shareVP(
            authorizationRequest = authorizationRequestWithoutStateProperty,
            vpTokenSigningResults = ldpvpTokenSigningResults,
            responseUri = authorizationRequest.responseUri!!
        )

        val authorizationResponse = AuthorizationResponse(
            presentationSubmission = PresentationSubmission(
                id = "649d581c-f291-4969-9cd5-2c27385a348f",
                definitionId = "649d581c-f891-4969-9cd5-2c27385a348f",
                descriptorMap = listOf(
                    DescriptorMap(
                        id = "456",
                        format = "ldp_vp",
                        path = "$",
                        pathNested = PathNested(
                            id = "456",
                            format = "ldp_vc",
                            path = "$.VerifiableCredential[0]"
                        )
                    ),
                    DescriptorMap(
                        id = "456",
                        format = "ldp_vp",
                        path = "$",
                        pathNested = PathNested(
                            id = "456",
                            format = "ldp_vc",
                            path = "$.VerifiableCredential[1]"
                        )
                    ),
                    DescriptorMap(
                        id = "789",
                        format = "ldp_vp",
                        path = "$",
                        pathNested = PathNested(
                            id = "789",
                            format = "ldp_vc",
                            path = "$.VerifiableCredential[2]"
                        )
                    )
                )
            ),
            vpToken = VPTokenType.VPTokenElement(
                value = LdpVPToken(
                    context = listOf("https://www.w3.org/2018/credentials/v1"),
                    type = listOf("VerifiablePresentation"),
                    verifiableCredential = listOf("credential1", "credential2", "credential3"),
                    id = "649d581c-f291-4969-9cd5-2c27385a348f",
                    holder = "",
                    proof = proof
                )
            ),
            state = null
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                url = authorizationRequest.responseUri!!,
                method = HttpMethod.POST,
                bodyParams = authorizationResponse.toJsonEncodedMap(),
                headers = expectedHeaders
            )
        }
    }

    @Test
    fun `should throw error when response type is not supported`() {
        val authorizationRequestWithNonVPTokenResponseType = AuthorizationRequest(
            clientId = "https://mock-verifier.com",
            responseType = "code",
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

        val actualException =
            assertThrows(Exceptions.InvalidData::class.java) {
                authorizationResponseHandler.shareVP(
                    authorizationRequest = authorizationRequestWithNonVPTokenResponseType,
                    vpTokenSigningResults = ldpvpTokenSigningResults,
                    responseUri = authorizationRequest.responseUri!!
                )
            }

        Assert.assertEquals(
            "Provided response_type - code is not supported",
            actualException.message
        )
    }

    @Test
    fun `should throw error when a credential format entry is not available in unsignedVPTokens but available in vpTokenSigningResults`() {
        setField(
            authorizationResponseHandler,
            "unsignedVPTokens",
            emptyMap<FormatType, UnsignedVPToken>()
        )
        val actualException =
            assertThrows(Exceptions.InvalidData::class.java) {
                authorizationResponseHandler.shareVP(
                    authorizationRequest = authorizationRequest,
                    vpTokenSigningResults = ldpvpTokenSigningResults,
                    responseUri = authorizationRequest.responseUri!!
                )
            }

        Assert.assertEquals(
            "unable to find the related credential format - LDP_VC in the unsignedVPTokens map",
            actualException.message
        )
    }

    @Test
    fun `should throw exception when credentials map is empty`() {
        val exception = Assert.assertThrows(Exceptions.InvalidData::class.java) {
            authorizationResponseHandler.constructUnsignedVPToken(
                credentialsMap = emptyMap<String, Map<FormatType, List<String>>>(),
                holderId = holderId,
                authorizationRequest = authorizationRequest,
                responseUri = responseUrl,
                signatureSuite = signatureSuite
            )
        }

        Assert.assertEquals(
            "Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request.",
            exception.message
        )
    }

    @Test
    fun `should successfully share VP with valid signing results`() {
        // First construct the unsigned tokens to populate internal state
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = credentialsMap,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite
        )

        val result = authorizationResponseHandler.shareVP(
            authorizationRequest = authorizationRequest,
            vpTokenSigningResults = mapOf(
                FormatType.LDP_VC to ldpVPTokenSigningResult,
                FormatType.MSO_MDOC to mdocVPTokenSigningResult
            ),
            responseUri = responseUrl
        )

        Assert.assertEquals("success", result)

        verify {
            ResponseModeBasedHandlerFactory.get("direct_post")
            mockResponseHandler.sendAuthorizationResponse(
                authorizationRequest = authorizationRequest,
                url = responseUrl,
                authorizationResponse = any(),
                walletNonce = any()
            )
        }
    }

    @Test
    fun `should throw exception when response type is not supported`() {
        // Setup mock authorization request with unsupported response type
        val mockInvalidRequest = mockk<AuthorizationRequest>()
        every { mockInvalidRequest.responseType } returns "code"

        // First construct the unsigned tokens to populate internal state
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = credentialsMap,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite
        )

        val exception = Assert.assertThrows(Exceptions.InvalidData::class.java) {
            authorizationResponseHandler.shareVP(
                authorizationRequest = mockInvalidRequest,
                vpTokenSigningResults = ldpvpTokenSigningResults,
                responseUri = responseUrl
            )
        }

        Assert.assertEquals("Provided response_type - code is not supported", exception.message)
    }

    @Test
    fun `should throw exception when format in signing results not found in unsigned tokens`() {
        // First construct the unsigned tokens with only LDP_VC
        val ldpOnlyCredentialsMap = mapOf<String, Map<FormatType, List<Any>>>(
            "input1" to mapOf(FormatType.LDP_VC to listOf(ldpCredential1))
        )

        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = ldpOnlyCredentialsMap,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite
        )

        // Try to sign with MSO_MDOC which wasn't in the unsigned tokens
        val exception = Assert.assertThrows(Exceptions.InvalidData::class.java) {
            authorizationResponseHandler.shareVP(
                authorizationRequest = authorizationRequest,
                vpTokenSigningResults = mdocvpTokenSigningResults,
                responseUri = responseUrl
            )
        }

        Assert.assertEquals(
            "unable to find the related credential format - MSO_MDOC in the unsignedVPTokens map",
            exception.message
        )
    }

    @Test
    fun `should throw exception when unsupported response mode is provided`() {
        // Create a mock authorization request with unsupported response mode
        val mockRequestWithUnsupportedMode = mockk<AuthorizationRequest>()
        every { mockRequestWithUnsupportedMode.responseType } returns "vp_token"
        every { mockRequestWithUnsupportedMode.nonce } returns "nonce"
        every { mockRequestWithUnsupportedMode.responseMode } returns "unsupported_mode"
        every { mockRequestWithUnsupportedMode.presentationDefinition.id } returns "pid"
        every { mockRequestWithUnsupportedMode.state } returns "state"

        // Mock the factory to throw exception for unsupported mode
        every { ResponseModeBasedHandlerFactory.get("unsupported_mode") } throws
                Exceptions.InvalidData("Unsupported response mode: unsupported_mode")

        // First construct the unsigned tokens to populate internal state
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = credentialsMap,
            holderId = holderId,
            authorizationRequest = authorizationRequest, // Use the valid request for this step
            responseUri = responseUrl,
            signatureSuite = signatureSuite
        )

        val exception = Assert.assertThrows(Exceptions.InvalidData::class.java) {
            authorizationResponseHandler.shareVP(
                authorizationRequest = mockRequestWithUnsupportedMode,
                vpTokenSigningResults = ldpvpTokenSigningResults,
                responseUri = responseUrl
            )
        }

        Assert.assertEquals("Unsupported response mode: unsupported_mode", exception.message)
    }

    @Test
    fun `should throw exception when unsupported response type is provided`() {
        // Create a mock authorization request with unsupported response mode
        val mockRequestWithUnsupportedMode = mockk<AuthorizationRequest>()
        every { mockRequestWithUnsupportedMode.responseType } returns "invalid_vp_token"

        // First construct the unsigned tokens to populate internal state
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = credentialsMap,
            holderId = holderId,
            authorizationRequest = authorizationRequest, // Use the valid request for this step
            responseUri = responseUrl,
            signatureSuite = signatureSuite
        )

        val exception = Assert.assertThrows(Exceptions.InvalidData::class.java) {
            authorizationResponseHandler.shareVP(
                authorizationRequest = mockRequestWithUnsupportedMode,
                vpTokenSigningResults = ldpvpTokenSigningResults,
                responseUri = responseUrl
            )
        }

        Assert.assertEquals(
            "Provided response_type - invalid_vp_token is not supported",
            exception.message
        )
    }

    @Test
    fun `should throw exception when network error occurs during response sending`() {
        // Mock network failure
        every {
            mockResponseHandler.sendAuthorizationResponse(any(), any(), any(), any())
        } throws IOException("Network connection failed")

        // First construct the unsigned tokens to populate internal state
        authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = credentialsMap,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite
        )

        val exception = Assert.assertThrows(IOException::class.java) {
            authorizationResponseHandler.shareVP(
                authorizationRequest = authorizationRequest,
                vpTokenSigningResults = ldpvpTokenSigningResults,
                responseUri = responseUrl
            )
        }

        Assert.assertEquals("Network connection failed", exception.message)
    }

    @Test
    fun `should ignore empty credential lists for input descriptors`() {
        // Create a map where one input descriptor has an empty credential list
        val mapWithEmptyCredList = mapOf<String, Map<FormatType, List<Any>>>(
            "input1" to mapOf(FormatType.LDP_VC to listOf(ldpCredential1)),
            "input2" to mapOf(FormatType.LDP_VC to emptyList())
        )

        // This should succeed, ignoring the empty list
        val result = authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = mapWithEmptyCredList,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite
        )

        Assert.assertNotNull(result)
        Assert.assertEquals(1, result.size)
        Assert.assertEquals(unsignedLdpVPToken, result[FormatType.LDP_VC])
    }
}

