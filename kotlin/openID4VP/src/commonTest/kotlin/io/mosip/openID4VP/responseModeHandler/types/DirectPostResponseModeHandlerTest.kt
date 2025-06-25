package io.mosip.openID4VP.responseModeHandler.types


import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.verify
import io.mosip.openID4VP.authorizationResponse.toJsonEncodedMap
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.constants.ContentType
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.testData.authorizationRequestForResponseModeJWT
import io.mosip.openID4VP.testData.authorizationResponse
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.assertThrows
import java.io.IOException

class DirectPostResponseModeHandlerTest {

    @Before
    fun setUp() {
        mockkObject(Logger)
        every { Logger.error(any(), any(), any()) } answers {  }

        mockkObject(NetworkManagerClient)
    }

    @After
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `validate should not throw any exception`() {
        val handler = DirectPostResponseModeHandler()
        handler.validate(null, null, false)
        // No assertion needed as method simply returns without doing anything
    }

    @Test
    fun `sendAuthorizationResponse should send request and return response body`() {
        // Arrange
        val handler = DirectPostResponseModeHandler()
        val responseUri = "https://example.com/response"
        val walletNonce = "test-nonce"
        val expectedResponse = "Response received"

        every {
            NetworkManagerClient.sendHTTPRequest(
                responseUri,
                HttpMethod.POST,
                any(),
                any()
            )
        } returns mapOf("body" to expectedResponse)

        // Act
        val actualResponse = handler.sendAuthorizationResponse(
            authorizationRequestForResponseModeJWT,
            responseUri,
            authorizationResponse,
            walletNonce
        )

        // Assert
        verify {
            NetworkManagerClient.sendHTTPRequest(
                url = responseUri,
                method = HttpMethod.POST,
                bodyParams = authorizationResponse.toJsonEncodedMap(),
                headers = mapOf("Content-Type" to ContentType.APPLICATION_FORM_URL_ENCODED.value)
            )
        }
        assertEquals(expectedResponse, actualResponse)
    }

    @Test
    fun `sendAuthorizationResponse should handle network errors`() {
        // Arrange
        val handler = DirectPostResponseModeHandler()
        val responseUri = "https://example.com/response"
        val walletNonce = "test-nonce"

        every {
            NetworkManagerClient.sendHTTPRequest(
                responseUri,
                HttpMethod.POST,
                any(),
                any()
            )
        } throws IOException("Network error")

        // Act & Assert
        assertThrows<IOException> {
            handler.sendAuthorizationResponse(
                authorizationRequestForResponseModeJWT,
                responseUri,
                authorizationResponse,
                walletNonce
            )
        }
    }

    @Test
    fun `sendAuthorizationResponse should handle empty response`() {
        // Arrange
        val handler = DirectPostResponseModeHandler()
        val responseUri = "https://example.com/response"
        val walletNonce = "test-nonce"

        every {
            NetworkManagerClient.sendHTTPRequest(
                responseUri,
                HttpMethod.POST,
                any(),
                any()
            )
        } returns mapOf("body" to "")

        // Act
        val actualResponse = handler.sendAuthorizationResponse(
            authorizationRequestForResponseModeJWT,
            responseUri,
            authorizationResponse,
            walletNonce
        )

        // Assert
        assertEquals("", actualResponse)
    }
}