//package io.mosip.openID4VP
//
//import android.util.Log
//import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer
//import io.mockk.clearAllMocks
//import io.mockk.every
//import io.mockk.mockkClass
//import io.mockk.mockkConstructor
//import io.mockk.mockkObject
//import io.mockk.mockkStatic
//import io.mockk.unmockkStatic
//import io.mockk.verify
//import io.mosip.openID4VP.common.UUIDGenerator
//import io.mosip.openID4VP.constants.FormatType
//import io.mosip.openID4VP.exceptions.Exceptions
//import io.mosip.openID4VP.constants.HttpMethod
//import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPTokenBuilder
//import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPTokenBuilder
//import io.mosip.openID4VP.common.URDNA2015Canonicalization
//import io.mosip.openID4VP.networkManager.NetworkManagerClient
//import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions.NetworkRequestFailed
//import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions.NetworkRequestTimeout
//import io.mosip.openID4VP.testData.authorizationRequest
//import io.mosip.openID4VP.testData.holderId
//import io.mosip.openID4VP.testData.setField
//import io.mosip.openID4VP.testData.unsignedVPTokens
//import io.mosip.openID4VP.testData.ldpvpTokenSigningResults
//import io.mosip.openID4VP.testData.ldpCredential1
//import io.mosip.openID4VP.testData.ldpCredential2
//import io.mosip.openID4VP.testData.ldpVPTokenSigningResult
//import io.mosip.openID4VP.testData.mdocCredential
//import io.mosip.openID4VP.testData.signatureSuite
//import io.mosip.openID4VP.testData.unsignedLdpVPToken
//import io.mosip.openID4VP.testData.unsignedMdocVPToken
//import io.mosip.openID4VP.testData.vpTokenSigningPayload
//import okhttp3.Headers
//import okhttp3.mockwebserver.MockWebServer
//import org.junit.After
//import org.junit.Assert.assertEquals
//import org.junit.Assert.assertThrows
//import org.junit.Before
//import org.junit.Ignore
//import org.junit.Test
//import java.util.UUID
//
//class OpenID4VPTest {
//
//    private lateinit var openID4VP: OpenID4VP
//    private val selectedLdpCredentialsList = mapOf(
//        "456" to mapOf(
//            FormatType.LDP_VC to listOf(
//                ldpCredential1,
//                ldpCredential2
//            )
//        ), "789" to mapOf(
//            FormatType.LDP_VC to listOf(
//                ldpCredential2
//            )
//        )
//    )
//    private val selectedMdocCredentialsList = mapOf(
//        "123" to mapOf(
//            FormatType.MSO_MDOC to listOf(mdocCredential)
//        )
//    )
//    private lateinit var mockWebServer: MockWebServer
//    private lateinit var actualException: Exception
//    private lateinit var expectedExceptionMessage: String
//
//    @Before
//    fun setUp() {
//        mockkObject(NetworkManagerClient)
//        openID4VP = OpenID4VP("test-OpenID4VP")
//        mockWebServer = MockWebServer()
//        mockWebServer.start(8080)
//        openID4VP.authorizationRequest = authorizationRequest
//        setField(
//            openID4VP,
//            "responseUri",
//            "https://mock-verifier.com/response-uri"
//        )
//
//        mockkStatic(Log::class)
//        every { Log.e(any(), any()) } answers {
//            val tag = arg<String>(0)
//            val msg = arg<String>(1)
//            println("Error: logTag: $tag | Message: $msg")
//            0
//        }
//
//        openID4VP.constructUnsignedVPToken(selectedLdpCredentialsList, holderId, signatureSuite )
//    }
//
//    @After
//    fun tearDown() {
//        clearAllMocks()
//        mockWebServer.shutdown()
//    }
//
//    @Test
//    fun `should construct VPToken using received selected verifiable credentials`() {
//        mockkObject(UUIDGenerator)
//        every { UUIDGenerator.generateUUID() } returns "test-uuid-123"
//
//        mockkConstructor(UnsignedLdpVPTokenBuilder::class)
//        every { anyConstructed<UnsignedLdpVPTokenBuilder>().build() } returns mapOf("unsignedVPToken" to unsignedLdpVPToken, "vpTokenSigningPayload" to vpTokenSigningPayload)
//
//        mockkConstructor(UnsignedMdocVPTokenBuilder::class)
//        every { anyConstructed<UnsignedMdocVPTokenBuilder>().build() } returns mapOf("unsignedVPToken" to unsignedMdocVPToken, "vpTokenSigningPayload" to listOf(mdocCredential))
//
//        val actualUnsignedVPTokens = openID4VP.constructUnsignedVPToken(selectedLdpCredentialsList + selectedMdocCredentialsList, holderId, signatureSuite)
//
//        val expectedUnsignedVPTokens = unsignedVPTokens
//        assertEquals(expectedUnsignedVPTokens[FormatType.LDP_VC]!!["unsignedVPToken"], actualUnsignedVPTokens[FormatType.LDP_VC])
//        assertEquals(expectedUnsignedVPTokens[FormatType.MSO_MDOC]!!["unsignedVPToken"], actualUnsignedVPTokens[FormatType.MSO_MDOC])
//    }
//
//    @Test
//    fun `should throw exception if Authorization Response request call returns the response with http status other than 200`() {
//        every {
//            NetworkManagerClient.sendHTTPRequest(
//                "https://mock-verifier.com/response-uri",
//                any(),
//                any(),
//                any()
//            )
//        } throws NetworkRequestFailed("Unknown error encountered")
//        expectedExceptionMessage =
//            "Network request failed with error response - Unknown error encountered"
//
//        actualException =
//            assertThrows(NetworkRequestFailed::class.java) {
//                openID4VP.shareVerifiablePresentation(ldpvpTokenSigningResults)
//            }
//
//        assertEquals(expectedExceptionMessage, actualException.message)
//    }
//
//    @Test
//    fun `should throw exception if Authorization Response request call takes more time to return response than specified time`() {
//        every {
//            NetworkManagerClient.sendHTTPRequest(
//                "https://mock-verifier.com/response-uri",
//                any(),
//                any(),
//                any()
//            )
//        } throws NetworkRequestTimeout()
//        expectedExceptionMessage = "VP sharing failed due to connection timeout"
//
//        actualException =
//            assertThrows(NetworkRequestTimeout::class.java) {
//                openID4VP.shareVerifiablePresentation(ldpvpTokenSigningResults)
//            }
//
//        assertEquals(expectedExceptionMessage, actualException.message)
//    }
//
//    @Test
//    fun `should get response if Verifiable Presentation is shared successfully to the Verifier`() {
//        every {
//            NetworkManagerClient.sendHTTPRequest(
//                "https://mock-verifier.com/response-uri",
//                any(),
//                any(),
//                any()
//            )
//        } returns mapOf(
//            "header" to Headers.Builder().add("content-type", "application/json").build(),
//            "body" to "Verifiable Presentation is shared successfully"
//        )
//        val expectedValue = "Verifiable Presentation is shared successfully"
//
//        val actualResponse = openID4VP.shareVerifiablePresentation(ldpvpTokenSigningResults)
//
//        assertEquals(expectedValue, actualResponse)
//    }
//
//    @Test
//    fun `should send the error to verifier when sendErrorToVerifier is called`() {
//        every {
//            NetworkManagerClient.sendHTTPRequest(
//                "https://mock-verifier.com/response-uri",
//                HttpMethod.POST,
//                any()
//            )
//        } returns mapOf("body" to "VP share success")
//
//        openID4VP.sendErrorToVerifier(Exceptions.InvalidData("Unsupported response_mode"))
//
//        verify {
//            NetworkManagerClient.sendHTTPRequest(
//                url = "https://mock-verifier.com/response-uri",
//                method = HttpMethod.POST,
//                bodyParams = mapOf("error" to "Unsupported response_mode"),
//            )
//        }
//    }
//}
//


package io.mosip.openID4VP

import android.util.Log
import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.Verifier
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponseHandler
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.VPResponseMetadata
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.URDNA2015Canonicalization
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.exceptions.Exceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions.NetworkRequestFailed
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions.NetworkRequestTimeout
import io.mosip.openID4VP.testData.*
import okhttp3.Headers
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import foundation.identity.jsonld.JsonLDObject

class OpenID4VPTest {

    private lateinit var openID4VP: OpenID4VP
    private val selectedLdpCredentialsList = mapOf(
        "456" to mapOf(
            FormatType.LDP_VC to listOf(
                ldpCredential1,
                ldpCredential2
            )
        ), "789" to mapOf(
            FormatType.LDP_VC to listOf(
                ldpCredential2
            )
        )
    )
    private val selectedMdocCredentialsList = mapOf(
        "123" to mapOf(
            FormatType.MSO_MDOC to listOf(mdocCredential)
        )
    )

    @Before
    fun setUp() {
        mockkObject(NetworkManagerClient)
        mockkStatic(Log::class)
        every { Log.e(any(), any()) } returns 0
        every { Log.d(any(), any()) } returns 0

        openID4VP = OpenID4VP("test-OpenID4VP")

        openID4VP.authorizationRequest = authorizationRequest
        setField(
            openID4VP,
            "responseUri",
            responseUrl
        )
    }

    @After
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should authenticate verifier successfully`() {
        mockkObject(AuthorizationRequest.Companion)

        val trustedVerifiers = trustedVerifiers
        val walletMetadata = walletMetadata

        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any(), any(), any(), any(), any()
            )
        } returns authorizationRequest

        val result = openID4VP.authenticateVerifier(
            "openid-vc://?request=test-request",
            trustedVerifiers,
            true,
            walletMetadata
        )

        assertEquals(authorizationRequest, result)
        verify {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                "openid-vc://?request=test-request", trustedVerifiers, walletMetadata, any(), true
            )
        }
    }

    @Test(expected = Exceptions.InvalidInput::class)
    fun `should throw exception during verifier authentication`() {
        mockkObject(AuthorizationRequest.Companion)
        mockkObject(NetworkManagerClient)

        val testException = Exceptions.InvalidInput("","Invalid authorization request")

        every {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                any(), any(), any(), any(), any()
            )
        } throws testException

        every {
            NetworkManagerClient.sendHTTPRequest(
                any(), any(), any()
            )
        } returns mapOf("body" to "Error sent")

        openID4VP.authenticateVerifier("openid-vc://?request=invalid", trustedVerifiers)
    }

    @Test
    fun `should construct unsigned VP token successfully`() {
        mockkObject(UUIDGenerator)
        mockkObject(URDNA2015Canonicalization)
        mockkStatic(JsonLDObject::class)

        every { UUIDGenerator.generateUUID() } returns "test-uuid-123"
        every { URDNA2015Canonicalization.canonicalize(any()) } returns "{\"valid\":\"json\"}"
        every { JsonLDObject.fromJson(any<String>()) } returns JsonLDObject()

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

        val actualUnsignedVPTokens = openID4VP.constructUnsignedVPToken(
            selectedLdpCredentialsList + selectedMdocCredentialsList,
            holderId,
            signatureSuite
        )

        val expectedUnsignedVPTokens = unsignedVPTokens
        assertEquals(expectedUnsignedVPTokens[FormatType.LDP_VC]!!["unsignedVPToken"], actualUnsignedVPTokens[FormatType.LDP_VC])
        assertEquals(expectedUnsignedVPTokens[FormatType.MSO_MDOC]!!["unsignedVPToken"], actualUnsignedVPTokens[FormatType.MSO_MDOC])
    }

    @Test(expected = Exceptions.InvalidData::class)
    fun `should throw exception during VP token construction with invalid data`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        val testException = Exceptions.InvalidData("Invalid credential format")

        every {
            mockHandler.constructUnsignedVPToken(any(), any(), any(), any(), any())
        } throws testException

        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        every {
            NetworkManagerClient.sendHTTPRequest(any(), any(), any())
        } returns mapOf("body" to "Error sent")

        openID4VP.constructUnsignedVPToken(selectedLdpCredentialsList, holderId, signatureSuite)
    }

    @Test
    fun `should send error to verifier successfully`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/response-uri",
                HttpMethod.POST,
                any()
            )
        } returns mapOf("body" to "VP share success")

        openID4VP.sendErrorToVerifier(Exceptions.InvalidData("Unsupported response_mode"))

        verify {
            NetworkManagerClient.sendHTTPRequest(
                url = "https://mock-verifier.com/response-uri",
                method = HttpMethod.POST,
                bodyParams = mapOf("error" to "Unsupported response_mode")
            )
        }
    }

    @Test
    fun `should handle exception during sending error to verifier`() {
        mockkObject(Logger)

        every {
            NetworkManagerClient.sendHTTPRequest(
                any(),
                any(),
                any()
            )
        } throws Exception("Network error")

        every { Logger.error(any(), any()) } just runs

        // Should not throw exception
        openID4VP.sendErrorToVerifier(Exceptions.InvalidData("Test error"))

        verify {
            Logger.error(
                any(),
                match<Exception> { it.message!!.contains("Unexpected error occurred") }
            )
        }
    }

    @Test
    fun `should handle deprecated constructVerifiablePresentationToken method`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()

        every {
            mockHandler.constructUnsignedVPTokenV1(any(), any(), any())
        } returns "Deprecated VP Token"

        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        val verifiableCredentials = mapOf("id1" to listOf("vc1", "vc2"))

        val result = openID4VP.constructVerifiablePresentationToken(verifiableCredentials)

        assertEquals("Deprecated VP Token", result)
    }

    @Test
    fun `should handle deprecated shareVerifiablePresentation method`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        val vpResponseMetadata = mockk<VPResponseMetadata>()

        every {
            mockHandler.shareVPV1(any(), any(), any())
        } returns "Deprecated VP Sharing Result"

        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        val result = openID4VP.shareVerifiablePresentation(vpResponseMetadata)

        assertEquals("Deprecated VP Sharing Result", result)
    }

    @Test(expected = Exceptions.InvalidData::class)
    fun `should handle exception in deprecated constructVerifiablePresentationToken method`() {
        val mockHandler = mockk<AuthorizationResponseHandler>()
        val exception = Exceptions.InvalidData("Invalid VC format")

        every {
            mockHandler.constructUnsignedVPTokenV1(any(), any(), any())
        } throws exception

        every {
            NetworkManagerClient.sendHTTPRequest(any(), any(), any())
        } returns mapOf("body" to "Error sent")

        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        openID4VP.constructVerifiablePresentationToken(mapOf("id1" to listOf("vc1")))
    }

    @Test
    fun `should handle empty credential list`() {
        mockkObject(UUIDGenerator)
        every { UUIDGenerator.generateUUID() } returns "test-uuid-123"

        val mockHandler = mockk<AuthorizationResponseHandler>()
        every {
            mockHandler.constructUnsignedVPToken(any(), any(), any(), any(), any())
        } returns emptyMap()

        setField(openID4VP, "authorizationResponseHandler", mockHandler)

        val result = openID4VP.constructUnsignedVPToken(emptyMap(), holderId, signatureSuite)

        assertTrue(result.isEmpty())
    }
}