package io.mosip.openID4VP.authorizationRequest

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.verify
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions.InvalidData
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions.InvalidVerifier
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions.MissingInput
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions.NetworkRequestFailed
import io.mosip.openID4VP.testData.*
import io.mosip.openID4VP.testData.createAuthorizationRequestObject
import io.mosip.openID4VP.testData.createUrlEncodedData
import okhttp3.Headers
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows

class AuthorizationRequestObjectObtainedByReference {
    private lateinit var openID4VP: OpenID4VP

    @Before
    fun setUp() {
        openID4VP = OpenID4VP("test-OpenID4VP")

        mockkObject(NetworkManagerClient.Companion)
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/verifier/get-presentation-definition",
                HTTP_METHOD.GET
            )
        } returns mapOf("body" to presentationDefinitionString)
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://resolver.identity.foundation/1.0/identifiers/did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
                HTTP_METHOD.GET
            )
        } returns mapOf("body" to didResponse)

        mockkStatic(android.util.Log::class)
        every { Log.e(any(), any()) } answers {
            val tag = arg<String>(0)
            val msg = arg<String>(1)
            println("Error: logTag: $tag | Message: $msg")
            0
        }
        every { Log.d(any(), any()) } answers {
            val tag = arg<String>(0)
            val msg = arg<String>(1)
            println("Error: logTag: $tag | Message: $msg")
            0
        }
    }

    @After
    fun tearDown() {
        clearAllMocks()
    }

    //Client Id scheme - DID
    @Test
    fun `should return Authorization Request if it has request uri and it is a valid authorization request in did client id scheme`() {
        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfDid
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt").build(),
            "body" to createAuthorizationRequestObject(ClientIdScheme.DID, authorizationRequestParamsMap)
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,
                true,
                ClientIdScheme.DID
            )

        assertDoesNotThrow {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }

    }

    @Test
    fun `should throw error if context type is wrong for request uri response`() {
        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfDid
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/json").build(),
            "body" to createAuthorizationRequestObject(ClientIdScheme.DID, authorizationRequestParamsMap)
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,
                true,
                ClientIdScheme.DID
            )

        val invalidInputException = assertThrows(InvalidData::class.java){
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }
        assertEquals("Authorization Request must be signed for given client_id_scheme", invalidInputException.message)
    }

    @Test
    fun `should throw exception when the call to request_uri method fails in did client id scheme`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                HTTP_METHOD.GET
            )
        } throws NetworkManagerClientExceptions.NetworkRequestTimeout()

        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfDid
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,true , ClientIdScheme.DID)


        val exceptionWhenRequestUriNetworkCallFails = assertThrows(Exception::class.java) {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                encodedAuthorizationRequest,
                trustedVerifiers,
                { _: String -> },
                false
            )
        }

        assertEquals(
            "VP sharing failed due to connection timeout",
            exceptionWhenRequestUriNetworkCallFails.message
        )
    }

    @Test
    fun `should throw exception when request_uri is not present in did client id scheme`() {

        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfDid
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.DID, authRequestWithDidByValue)


        val missingInputException = assertThrows(MissingInput::class.java) {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                encodedAuthorizationRequest,
                trustedVerifiers,
                { _: String -> },
                false
            )
        }

        assertEquals(
            "Missing Input: request_uri param is required",
            missingInputException.message
        )
    }

    @Test
    fun `should make call to request_uri with the request_uri_method when the fields are available in did client id scheme`() {
        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfDid
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns  mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt").build(),
            "body" to createAuthorizationRequestObject(ClientIdScheme.DID, authorizationRequestParamsMap)
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,true, ClientIdScheme.REDIRECT_URI )


        openID4VP.authenticateVerifier(
            encodedAuthorizationRequest,
            trustedVerifiers,
            shouldValidateClient = true
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                HTTP_METHOD.GET
            )
        }
    }

    @Test
    fun `should throw error if  request_uri is not valid in authorization request`() {
        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfDid + mapOf(REQUEST_URI.value to "test-data")

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,true, ClientIdScheme.REDIRECT_URI )


        val exception = assertThrows<InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }

        assertEquals("request_uri data is not valid", exception.message)
    }

    @Test
    fun `should make a call to request_uri in get http call if request_uri_method is not available in did client id scheme`() {
        val authorizationRequestParamsMap = requestParams.minus("request_uri_method") + clientIdAndSchemeOfDid
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns  mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt").build(),
            "body" to createAuthorizationRequestObject(ClientIdScheme.DID, authorizationRequestParamsMap)
        )
        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            ClientIdScheme.DID
        )

        openID4VP.authenticateVerifier(
            encodedAuthorizationRequest,
            trustedVerifiers,
            shouldValidateClient = true
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                HTTP_METHOD.GET
            )
        }

    }

    @Test
    fun `should throw invalid verifier for invalid client id in authorization request in did client id scheme`() {
        val authorizationRequestParamsMap = requestParams + mapOf(
            CLIENT_ID.value to "invaliddid:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
            CLIENT_ID_SCHEME.value to ClientIdScheme.DID.value
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,
                true,
                ClientIdScheme.DID
            )

        val exception = assertThrows<InvalidVerifier> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }

        assertEquals("Client ID should start with did prefix if client_id_scheme is did", exception.message)

    }

    @Test
    fun `should throw exception when the client_id validation fails while obtaining Authorization request object by reference in did client id scheme`() {
        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, any())
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt").build(),
            "body" to createAuthorizationRequestObject(
                ClientIdScheme.DID, requestParams + mapOf(
                    CLIENT_ID.value to "wrong-client-id",
                    CLIENT_ID_SCHEME.value to ClientIdScheme.DID.value
                )
            )
        )

        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfDid
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,true , ClientIdScheme.DID)


        val exception = assertThrows(InvalidData::class.java) {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }

        assertEquals(
            "Client Id mismatch in Authorization Request parameter and the Request Object",
            exception.message
        )
    }

    @Test
    fun `should throw exception when the client_id_scheme validation fails while obtaining Authorization request object by reference in did client id scheme`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns  mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt").build(),
            "body" to createAuthorizationRequestObject(ClientIdScheme.DID, requestParams + mapOf(
                CLIENT_ID.value to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
                CLIENT_ID_SCHEME.value to ClientIdScheme.PRE_REGISTERED.value
            ))
        )

        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfDid
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,true , ClientIdScheme.DID)

        val exception = assertThrows(InvalidData::class.java) {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }

        assertEquals(
            "Client Id Scheme mismatch in Authorization Request parameter and the Request Object",
            exception.message
        )
    }

    //Client Id scheme - Pre-registered
    @Test
    fun `should return back authorization request successfully when authorization request is obtained by reference in pre-registered client id scheme`() {

        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfPreRegistered
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                HTTP_METHOD.GET
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/json").build(),
            "body" to createAuthorizationRequestObject(ClientIdScheme.PRE_REGISTERED, authorizationRequestParamsMap)
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,true , ClientIdScheme.DID)


        assertDoesNotThrow {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                encodedAuthorizationRequest,
                trustedVerifiers,
                { _: String -> },
                false
            )
        }
    }

    @Test
    fun `should throw error when signed authorization request is obtained by reference in pre-registered client id scheme`() {

        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfPreRegistered
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                HTTP_METHOD.GET
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt").build(),
            "body" to createAuthorizationRequestObject(ClientIdScheme.PRE_REGISTERED, authorizationRequestParamsMap)
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,true , ClientIdScheme.DID)


        assertThrows<InvalidData> {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                encodedAuthorizationRequest,
                trustedVerifiers,
                { _: String -> },
                false
            )
        }
    }

    @Test
    fun `should throw error when signed authorization request is obtained by reference in redirect client id scheme`() {

        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfReDirectUri
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                HTTP_METHOD.GET
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/oauth-authz-req+jwt").build(),
            "body" to createAuthorizationRequestObject(ClientIdScheme.REDIRECT_URI, authorizationRequestParamsMap)
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,true , ClientIdScheme.DID)


        assertThrows<InvalidData> {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                encodedAuthorizationRequest,
                trustedVerifiers,
                { _: String -> },
                false
            )
        }
    }

    //Client Id - Pre-registered
    @Test
    fun `should validate client_id when authorization request is obtained by reference in pre-registered client id scheme`() {
        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, any())
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/json").build(),
            "body" to createAuthorizationRequestObject(
                ClientIdScheme.PRE_REGISTERED, requestParams + mapOf(
                    CLIENT_ID.value to "wrong-client-id",
                    CLIENT_ID_SCHEME.value to ClientIdScheme.PRE_REGISTERED.value
                )
            )
        )

        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfPreRegistered
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,true , ClientIdScheme.PRE_REGISTERED)

        val invalidClientIdException =
            assertThrows(InvalidData::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest,
                    trustedVerifiers,
                    shouldValidateClient = true
                )
            }

        assertEquals(
            "Client Id mismatch in Authorization Request parameter and the Request Object",
            invalidClientIdException.message
        )
    }

    //Client Id scheme - Pre-registered
    @Test
    fun `should validate client_id_scheme when authorization request is obtained by reference in pre-registered client id scheme`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/json").build(),
            "body" to createAuthorizationRequestObject(
                ClientIdScheme.PRE_REGISTERED, requestParams + mapOf(
                    CLIENT_ID.value to "https://verifier.env1.net",
                    CLIENT_ID_SCHEME.value to ClientIdScheme.DID.value
                )
            )
        )

        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfPreRegistered
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,true , ClientIdScheme.PRE_REGISTERED)

        val invalidClientIsSchemeException =
            assertThrows(InvalidData::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest,
                    trustedVerifiers,
                    shouldValidateClient = true
                )
            }

        assertEquals(
            "Client Id Scheme mismatch in Authorization Request parameter and the Request Object",
            invalidClientIsSchemeException.message
        )
    }

    @Test
    fun `should validate client_id_scheme when authorization request is obtained by reference in pre-registered client id scheme and it is null in qr code data`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/json").build(),
            "body" to createAuthorizationRequestObject(
                ClientIdScheme.PRE_REGISTERED, requestParams + mapOf(
                    CLIENT_ID.value to "https://verifier.env1.net",
                    CLIENT_ID_SCHEME.value to ClientIdScheme.DID.value
                )
            )
        )

        val authorizationRequestParamsMap = requestParams + mapOf(
            CLIENT_ID.value to "https://verifier.env1.net",
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,true , ClientIdScheme.PRE_REGISTERED)

        val invalidClientIsSchemeException =
            assertThrows(InvalidData::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest,
                    trustedVerifiers,
                    shouldValidateClient = true
                )
            }

        assertEquals(
            "Client Id Scheme mismatch in Authorization Request parameter and the Request Object",
            invalidClientIsSchemeException.message
        )
    }
}

