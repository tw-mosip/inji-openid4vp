package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import android.util.Log
import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.VPFormatSupported
import io.mosip.openID4VP.constants.ContentType
import io.mosip.openID4VP.exceptions.Exceptions
import io.mosip.openID4VP.exceptions.Exceptions.MissingInput
import io.mosip.openID4VP.jwt.jws.JWSHandler
import io.mosip.openID4VP.jwt.keyResolver.types.DidPublicKeyResolver
import io.mosip.openID4VP.testData.clientMetadataString
import io.mosip.openID4VP.testData.didUrl
import io.mosip.openID4VP.testData.jws
import io.mosip.openID4VP.testData.presentationDefinitionString
import okhttp3.Headers
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.Assertions.*

class DidSchemeAuthorizationRequestHandlerTest {

    private lateinit var authorizationRequestParameters: MutableMap<String, Any>
    private lateinit var walletMetadata: WalletMetadata
    private val setResponseUri: (String) -> Unit = mockk(relaxed = true)

    @Before
    fun setup() {
        mockkStatic(Log::class)
        every { Log.e(any(), any()) } answers {
            println("Error: logTag: ${arg<String>(0)} | Message: ${arg<String>(1)}")
            0
        }

        authorizationRequestParameters = mutableMapOf(
            CLIENT_ID.value to didUrl,
            RESPONSE_TYPE.value to "vp_token",
            RESPONSE_URI.value to "https://example.com/response",
            PRESENTATION_DEFINITION.value to presentationDefinitionString,
            RESPONSE_MODE.value to "direct_post",
            NONCE.value to "VbRRB/LTxLiXmVNZuyMO8A==",
            STATE.value to "+mRQe1d6pBoJqF6Ab28klg==",
            CLIENT_METADATA.value to clientMetadataString
        )

        walletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf("jwt_vp" to VPFormatSupported(listOf("ES256"))),
            clientIdSchemesSupported = listOf("did"),
            requestObjectSigningAlgValuesSupported = listOf("ES256", "RS256")
        )

        mockkConstructor(JWSHandler::class)
        mockkConstructor(DidPublicKeyResolver::class)
        every { anyConstructed<JWSHandler>().extractDataJsonFromJws(JWSHandler.JwsPart.HEADER) } returns mutableMapOf("alg" to "ES256")
        every { anyConstructed<JWSHandler>().extractDataJsonFromJws(JWSHandler.JwsPart.PAYLOAD) } returns authorizationRequestParameters

    }

    @Test
    fun `validateRequestUriResponse should succeed with valid JWS and content type`() {
        // Arrange
        val handler = DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters, walletMetadata, setResponseUri
        )

        val headers = Headers.Builder()
            .add("content-type", ContentType.APPLICATION_JWT.value)
            .build()

        val requestUriResponse = mapOf(
            "header" to headers,
            "body" to jws
        )

        every { anyConstructed<JWSHandler>().verify() } just runs

        assertDoesNotThrow { handler.validateRequestUriResponse(requestUriResponse) }

        verify { anyConstructed<JWSHandler>().extractDataJsonFromJws(JWSHandler.JwsPart.HEADER) }
        verify { anyConstructed<JWSHandler>().extractDataJsonFromJws(JWSHandler.JwsPart.PAYLOAD) }
    }

    @Test
    fun `validateRequestUriResponse should throw exception with invalid content type`() {
        // Arrange
        val handler = DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters, walletMetadata, setResponseUri
        )

        val headers = Headers.Builder()
            .add("content-type", ContentType.APPLICATION_JSON.value)
            .build()

        val requestUriResponse = mapOf(
            "header" to headers,
            "body" to jws
        )

        // Act & Assert
        val exception = assertThrows<Exception> { handler.validateRequestUriResponse(requestUriResponse) }
        assertTrue(exception.message?.contains("Authorization Request must be signed") == true)
    }

    @Test
    fun `validateRequestUriResponse should throw exception when body is not JWS`() {

        val handler = DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters, walletMetadata, setResponseUri
        )

        val headers = Headers.Builder()
            .add("content-type", ContentType.APPLICATION_JWT.value)
            .build()

        val requestUriResponse = mapOf(
            "header" to headers,
            "body" to "{\"client_id\":\"didUrl\"}"
        )

        // Act & Assert
        val exception = assertThrows<Exception> { handler.validateRequestUriResponse(requestUriResponse) }
        assertTrue(exception.message?.contains("Authorization Request must be signed") == true)
    }

    @Test
    fun `validateRequestUriResponse should throw exception when JWS verification fails`() {
        // Arrange
        every { anyConstructed<JWSHandler>().verify() } throws Exception("Invalid signature")

        val handler = DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters, walletMetadata, setResponseUri
        )

        val headers = Headers.Builder()
            .add("content-type", ContentType.APPLICATION_JWT.value)
            .build()

        val requestUriResponse = mapOf(
            "header" to headers,
            "body" to jws
        )

        // Act & Assert
        assertThrows<Exception> { handler.validateRequestUriResponse(requestUriResponse) }
    }

    @Test
    fun `validateRequestUriResponse should throw exception when requestUriResponse is empty`() {
        // Arrange
        val handler = DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters, walletMetadata, setResponseUri
        )

        // Act & Assert
        val exception = assertThrows<MissingInput> { handler.validateRequestUriResponse(emptyMap()) }
        assertEquals(exception.message, "Missing Input: request_uri param is required")
    }

    @Test
    fun `validateRequestUriResponse should throw exception when signing algorithm is not supported`() {
        // Arrange
        every { anyConstructed<JWSHandler>().verify() } just runs
        // Then mock the header extraction to return unsupported algorithm
        every { anyConstructed<JWSHandler>().extractDataJsonFromJws(JWSHandler.JwsPart.HEADER) } returns mutableMapOf("alg" to "HS256")


        val handler = DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters, walletMetadata, setResponseUri
        )

        val field = handler.javaClass.superclass.getDeclaredField("shouldValidateWithWalletMetadata")
        field.isAccessible = true
        field.set(handler, true)


        val headers = Headers.Builder()
            .add("content-type", ContentType.APPLICATION_JWT.value)
            .build()

        val requestUriResponse = mapOf(
            "header" to headers,
            "body" to jws
        )

        // Act & Assert
        val exception = assertThrows<Exceptions.InvalidData> { handler.validateRequestUriResponse(requestUriResponse) }
        assertEquals(exception.message, "request_object_signing_alg is not support by wallet")
    }

    @Test
    fun `process should return wallet metadata when requestObjectSigningAlgValuesSupported is valid`() {
        // Arrange
        val handler = DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters, walletMetadata, setResponseUri
        )

        // Act
        val result = handler.process(walletMetadata)

        // Assert
        assertEquals(walletMetadata, result)
        assertEquals(listOf("ES256", "RS256"), result.requestObjectSigningAlgValuesSupported)
    }

    @Test
    fun `process should throw exception when requestObjectSigningAlgValuesSupported is null`() {
        // Arrange
        val handler = DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters, walletMetadata, setResponseUri
        )

        val invalidWalletMetadata = walletMetadata.copy(
            requestObjectSigningAlgValuesSupported = null
        )

        // Act & Assert
        val exception = assertThrows<Exception> { handler.process(invalidWalletMetadata) }
        assertTrue(exception.message?.contains("request_object_signing_alg_values_supported is not present") == true)
    }

    @Test
    fun `process should throw exception when requestObjectSigningAlgValuesSupported is empty`() {
        // Arrange
        val handler = DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters, walletMetadata, setResponseUri
        )

        val invalidWalletMetadata = walletMetadata.copy(
            requestObjectSigningAlgValuesSupported = emptyList()
        )

        // Act & Assert
        val exception = assertThrows<Exception> { handler.process(invalidWalletMetadata) }
        assertTrue(exception.message?.contains("request_object_signing_alg_values_supported is not present") == true)
    }

    @Test
    fun `getHeadersForAuthorizationRequestUri should return correct headers`() {
        // Arrange
        val handler = DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters, walletMetadata, setResponseUri
        )

        // Act
        val headers = handler.getHeadersForAuthorizationRequestUri()

        // Assert
        assertEquals(ContentType.APPLICATION_FORM_URL_ENCODED.value, headers["content-type"])
        assertEquals(ContentType.APPLICATION_JWT.value, headers["accept"])
    }
}