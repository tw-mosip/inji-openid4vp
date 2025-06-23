package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import android.util.Log
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.Verifier
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.VPFormatSupported
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.constants.ContentType
import okhttp3.Headers
import org.junit.jupiter.api.Assertions.*
import org.junit.Test
import org.junit.jupiter.api.assertThrows
import io.mockk.*
import io.mosip.openID4VP.testData.clientMetadataString
import io.mosip.openID4VP.testData.presentationDefinitionString
import io.mosip.openID4VP.testData.requestUrl
import io.mosip.openID4VP.testData.responseUrl
import io.mosip.openID4VP.testData.trustedVerifiers
import org.junit.Before

class PreRegisteredSchemeAuthorizationRequestHandlerTest {

    private lateinit var authorizationRequestParameters: MutableMap<String, Any>
    private lateinit var walletMetadata: WalletMetadata
    private val setResponseUri: (String) -> Unit = mockk(relaxed = true)
    private val validClientId = "mock-client"

    @Before
    fun setup() {
        mockkStatic(Log::class)
        every { Log.e(any(), any()) } answers {
            val tag = arg<String>(0)
            val msg = arg<String>(1)
            println("Error: logTag: $tag | Message: $msg")
            0
        }
        authorizationRequestParameters = mutableMapOf(
            CLIENT_ID.value to validClientId,
            RESPONSE_TYPE.value to "vp_token",
            RESPONSE_URI.value to responseUrl,
            PRESENTATION_DEFINITION.value to presentationDefinitionString,
            RESPONSE_MODE.value to "direct_post",
            NONCE.value to "VbRRB/LTxLiXmVNZuyMO8A==",
            STATE.value to "+mRQe1d6pBoJqF6Ab28klg==",
            CLIENT_METADATA.value to clientMetadataString
        )

        walletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf("jwt_vp" to VPFormatSupported(listOf("ES256"))),
            clientIdSchemesSupported = listOf("pre-registered")
        )
    }

    @Test
    fun `validateClientId should pass when client ID is trusted and validation is enabled`() {
        // Arrange
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers, authorizationRequestParameters, walletMetadata, true, setResponseUri
        )

        // Act & Assert - no exception thrown
        assertDoesNotThrow { handler.validateClientId() }
    }

    @Test
    fun `validateClientId should skip validation when shouldValidateClient is false`() {
        // Arrange
        authorizationRequestParameters[CLIENT_ID.value] = "untrusted-client-id"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers, authorizationRequestParameters, walletMetadata, false, setResponseUri
        )

        // Act & Assert - no exception thrown
        assertDoesNotThrow { handler.validateClientId() }
    }

    @Test
    fun `validateClientId should throw exception when client ID is not trusted`() {
        // Arrange
        authorizationRequestParameters[CLIENT_ID.value] = "untrusted-client-id"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers, authorizationRequestParameters, walletMetadata, true, setResponseUri
        )

        // Act & Assert
        val exception = assertThrows<Exception> { handler.validateClientId() }
        assertTrue(exception.message?.contains("Verifier is not trusted") == true)
    }

    @Test
    fun `validateRequestUriResponse should accept valid JSON response`() {
        // Arrange
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers, authorizationRequestParameters, walletMetadata, true, setResponseUri
        )

        val headers = Headers.Builder()
            .add("content-type", ContentType.APPLICATION_JSON.value)
            .build()

        val responseBody = """{"client_id":"$validClientId","response_uri":"$responseUrl"}"""

        val requestUriResponse = mapOf(
            "header" to headers,
            "body" to responseBody
        )

        // Act & Assert - no exception thrown
        assertDoesNotThrow { handler.validateRequestUriResponse(requestUriResponse) }
    }

    @Test
    fun `validateRequestUriResponse should throw exception for invalid content type`() {
        // Arrange
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers, authorizationRequestParameters, walletMetadata, true, setResponseUri
        )

        val headers = Headers.Builder()
            .add("content-type", "application/jwt")
            .build()

        val responseBody = """{"client_id":"$validClientId","response_uri":"$responseUrl"}"""

        val requestUriResponse = mapOf(
            "header" to headers,
            "body" to responseBody
        )

        // Act & Assert
        val exception = assertThrows<Exception> { handler.validateRequestUriResponse(requestUriResponse) }
        assertTrue(exception.message?.contains("Authorization Request must not be signed") == true)
    }

    @Test
    fun `process should return wallet metadata with null requestObjectSigningAlgValuesSupported`() {
        // Arrange
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers, authorizationRequestParameters, walletMetadata, true, setResponseUri
        )

        // Act
        val processedMetadata = handler.process(walletMetadata.copy(
            requestObjectSigningAlgValuesSupported = listOf("ES256")
        ))

        // Assert
        assertNull(processedMetadata.requestObjectSigningAlgValuesSupported)
    }

    @Test
    fun `getHeadersForAuthorizationRequestUri should return correct headers`() {
        // Arrange
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers, authorizationRequestParameters, walletMetadata, true, setResponseUri
        )

        // Act
        val headers = handler.getHeadersForAuthorizationRequestUri()

        // Assert
        assertEquals(ContentType.APPLICATION_FORM_URL_ENCODED.value, headers["content-type"])
        assertEquals(ContentType.APPLICATION_JSON.value, headers["accept"])
    }

    @Test
    fun `validateAndParseRequestFields should pass for trusted client with valid response URI`() {
        // Arrange
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers, authorizationRequestParameters, walletMetadata, true, setResponseUri
        )

        // Act & Assert - no exception thrown
        assertDoesNotThrow { handler.validateAndParseRequestFields() }
    }

    @Test
    fun `validateAndParseRequestFields should throw exception when response URI is not trusted`() {
        // Arrange
        authorizationRequestParameters[RESPONSE_URI.value] = "https://untrusted.verifier.com/response"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers, authorizationRequestParameters, walletMetadata, true, setResponseUri
        )

        // Act & Assert
        val exception = assertThrows<Exception> { handler.validateAndParseRequestFields() }
        assertTrue(exception.message?.contains("Verifier is not trusted") == true)
    }

    @Test
    fun `validateAndParseRequestFields should skip validation when shouldValidateClient is false`() {
        // Arrange
        authorizationRequestParameters[RESPONSE_URI.value] = "https://untrusted.verifier.com/response"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers, authorizationRequestParameters, walletMetadata, false, setResponseUri
        )

        // Act & Assert - no exception thrown
        assertDoesNotThrow { handler.validateAndParseRequestFields() }
    }
}