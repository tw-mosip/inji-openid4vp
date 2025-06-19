package io.mosip.openID4VP.authorizationResponse

import android.util.Log
import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPTokenBuilder
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.exceptions.Exceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandler
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory
import io.mosip.openID4VP.testData.*
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import java.io.IOException
import org.junit.Assert.assertTrue

class AuthorizationResponseHandlerTest1 {

    private lateinit var authorizationResponseHandler: AuthorizationResponseHandler
    private val mockResponseHandler = mockk<ResponseModeBasedHandler>()

    private val credentialsMap = mapOf(
        "input1" to mapOf(FormatType.LDP_VC to listOf(ldpCredential1)),
        "input2" to mapOf(FormatType.MSO_MDOC to listOf(mdocCredential))
    )

    @Before
    fun setUp() {
        authorizationResponseHandler = AuthorizationResponseHandler()

        mockkStatic(Log::class)
        every { Log.e(any(), any()) } returns 0

        mockkObject(UUIDGenerator)
        every { UUIDGenerator.generateUUID() } returns "test-uuid-123"

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

        mockkConstructor(LdpVPTokenBuilder::class)
        every { anyConstructed<LdpVPTokenBuilder>().build() } returns ldpVPToken

        mockkConstructor(MdocVPTokenBuilder::class)
        every { anyConstructed<MdocVPTokenBuilder>().build() } returns mdocVPToken

        mockkObject(ResponseModeBasedHandlerFactory)
        every { ResponseModeBasedHandlerFactory.get(any()) } returns mockResponseHandler
        every { mockResponseHandler.sendAuthorizationResponse(any(), any(), any(), any()) } returns "success"

        mockkObject(NetworkManagerClient)
    }

    @After
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should successfully construct unsigned VP tokens for both LDP_VC and MSO_MDOC formats`() {
        val result = authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = credentialsMap,
            holderId = holderId,
            authorizationRequest = authorizationRequest,
            responseUri = responseUrl,
            signatureSuite = signatureSuite
        )

        assertNotNull(result)
        assertEquals(2, result.size)
        assertEquals(unsignedLdpVPToken, result[FormatType.LDP_VC])
        assertEquals(unsignedMdocVPToken, result[FormatType.MSO_MDOC])

        verify {
            anyConstructed<UnsignedLdpVPTokenBuilder>().build()
            anyConstructed<UnsignedMdocVPTokenBuilder>().build()
        }
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

        assertEquals(
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

        assertEquals("success", result)

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

        assertEquals("Provided response_type - code is not supported", exception.message)
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

        assertEquals(
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

        assertEquals("Unsupported response mode: unsupported_mode", exception.message)
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

        assertEquals("Provided response_type - invalid_vp_token is not supported", exception.message)
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

        assertEquals("Network connection failed", exception.message)
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

        assertNotNull(result)
        assertEquals(1, result.size)
        assertEquals(unsignedLdpVPToken, result[FormatType.LDP_VC])
    }
}