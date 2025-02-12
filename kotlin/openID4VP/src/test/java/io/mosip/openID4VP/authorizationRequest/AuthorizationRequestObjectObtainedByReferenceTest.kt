package io.mosip.openID4VP.authorizationRequest

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.verify
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions
import io.mosip.openID4VP.testScripts.JWTUtil.Companion.createAuthorizationRequestObject
import io.mosip.openID4VP.testScripts.clientMetadata
import io.mosip.openID4VP.testScripts.createEncodedAuthorizationRequest
import io.mosip.openID4VP.testScripts.didResponse
import io.mosip.openID4VP.testScripts.presentationDefinition
import io.mosip.openID4VP.testScripts.trustedVerifiers
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertDoesNotThrow

class AuthorizationRequestObjectObtainedByReference {
    private lateinit var openID4VP: OpenID4VP

    val requestParams: Map<String, String> = mapOf(
        "client_id" to "https://mock-verifier.com",
        "client_id_scheme" to "redirect_uri",
        "redirect_uri" to "https://mock-verifier.com",
        "response_uri" to "https://mock-verifier.com",
        "request_uri" to "https://verifier/verifier/get-auth-request-obj",
        "request_uri_method" to "get",
        "presentation_definition" to presentationDefinition,
        "response_type" to "vp_token",
        "response_mode" to "direct_post",
        "nonce" to "VbRRB/LTxLiXmVNZuyMO8A==",
        "state" to "+mRQe1d6pBoJqF6Ab28klg==",
        "client_metadata" to clientMetadata
    )

    @Before
    fun setUp() {
        openID4VP = OpenID4VP("test-OpenID4VP")

        mockkObject(NetworkManagerClient.Companion)
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://verifier/verifier/presentation_definition_uri",
                HTTP_METHOD.GET
            )
        } returns presentationDefinition
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://resolver.identity.foundation/1.0/identifiers/did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
                HTTP_METHOD.GET
            )
        } returns didResponse

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
        val authorizationRequestParamsMap = requestParams + mapOf(
            "client_id" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
            "client_id_scheme" to ClientIdScheme.DID.value
        )
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://verifier/verifier/get-auth-request-obj",
                any()
            )
        } returns createAuthorizationRequestObject(ClientIdScheme.DID, authorizationRequestParamsMap)

        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(
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
    fun `should throw exception when the call to request_uri method fails in did client id scheme`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://verifier/verifier/get-auth-request-obj",
                HTTP_METHOD.GET
            )
        } throws NetworkManagerClientExceptions.NetworkRequestTimeout()

        val authorizationRequestParamsMap = requestParams + mapOf(
            "client_id" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
            "client_id_scheme" to ClientIdScheme.DID.value
        )
        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(authorizationRequestParamsMap,true , ClientIdScheme.DID)


        val exceptionWhenRequestUriNetworkCallFails = assertThrows(Exception::class.java) {
            AuthorizationRequest.validateAndGetAuthorizationRequest(
                encodedAuthorizationRequest,
                { _: String -> },
                trustedVerifiers,
                false
            )
        }

        assertEquals(
            "VP sharing failed due to connection timeout",
            exceptionWhenRequestUriNetworkCallFails.message
        )
    }

    @Test
    fun `should make call to request_uri with the request_uri_method when the fields are available in did client id scheme`() {
        val authorizationRequestParamsMap = requestParams + mapOf(
            "client_id" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
            "client_id_scheme" to ClientIdScheme.DID.value
        )
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://verifier/verifier/get-auth-request-obj",
                any()
            )
        } returns createAuthorizationRequestObject(ClientIdScheme.DID, authorizationRequestParamsMap)

        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(authorizationRequestParamsMap,true, ClientIdScheme.REDIRECT_URI )


        openID4VP.authenticateVerifier(
            encodedAuthorizationRequest,
            trustedVerifiers,
            shouldValidateClient = true
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                "https://verifier/verifier/get-auth-request-obj",
                HTTP_METHOD.GET
            )
        }
    }

    @Test
    fun `should make a call to request_uri in get http call if request_uri_method is not available in did client id scheme`() {
        val authorizationRequestParamsMap = requestParams.minus("request_uri_method") + mapOf(
            "client_id" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
            "client_id_scheme" to ClientIdScheme.DID.value
        )
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://verifier/verifier/get-auth-request-obj",
                any()
            )
        } returns createAuthorizationRequestObject(ClientIdScheme.DID, authorizationRequestParamsMap)

        val encodedAuthorizationRequest = createEncodedAuthorizationRequest(
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
                "https://verifier/verifier/get-auth-request-obj",
                HTTP_METHOD.GET
            )
        }
    }

    @Test
    fun `should throw exception when the client_id validation fails while obtaining Authorization request object by reference in did client id scheme`() {
       every {
            NetworkManagerClient.sendHTTPRequest(
                "https://verifier/verifier/get-auth-request-obj",
                any()
            )
        } returns createAuthorizationRequestObject(ClientIdScheme.DID, requestParams + mapOf(
            "client_id" to "wrong-client-id",
            "client_id_scheme" to ClientIdScheme.DID.value
        ))

        val authorizationRequestParamsMap = requestParams + mapOf(
            "client_id" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
            "client_id_scheme" to ClientIdScheme.DID.value
        )
        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(authorizationRequestParamsMap,true , ClientIdScheme.DID)


        val exception = assertThrows(AuthorizationRequestExceptions.InvalidData::class.java) {
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
                "https://verifier/verifier/get-auth-request-obj",
                any()
            )
        } returns createAuthorizationRequestObject(ClientIdScheme.DID, requestParams + mapOf(
            "client_id" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
            "client_id_scheme" to ClientIdScheme.PRE_REGISTERED.value
        ))

        val authorizationRequestParamsMap = requestParams + mapOf(
            "client_id" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
            "client_id_scheme" to ClientIdScheme.DID.value
        )
        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(authorizationRequestParamsMap,true , ClientIdScheme.DID)

        val exception = assertThrows(AuthorizationRequestExceptions.InvalidData::class.java) {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }

        assertEquals(
            "Client Id scheme mismatch in Authorization Request parameter and the Request Object",
            exception.message
        )
    }

    //Client Id scheme - Pre-registered
    @Test
    fun `should return back authorization request successfully when authorization request is obtained by reference in pre-registered client id scheme`() {
        val authorizationRequestParamsMap = requestParams + mapOf(
            "client_id" to "https://mock-client-id",
            "client_id_scheme" to ClientIdScheme.PRE_REGISTERED.value
        )
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://verifier/verifier/get-auth-request-obj",
                HTTP_METHOD.GET
            )
        } returns createAuthorizationRequestObject(ClientIdScheme.PRE_REGISTERED, authorizationRequestParamsMap)

        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(authorizationRequestParamsMap,true , ClientIdScheme.DID)


        assertDoesNotThrow {
            AuthorizationRequest.validateAndGetAuthorizationRequest(
                encodedAuthorizationRequest,
                { _: String -> },
                trustedVerifiers,
                false
            )
        }
    }

    /*@Test
    fun `should validate client_id and client_id scheme when authorization request is obtained by reference in pre-registered client id scheme`() {
        val authorizationRequestObjectWithDifferentClientIdSchemeFromAuthorizationRequestParam =
            "eyJwcmVzZW50YXRpb25fZGVmaW5pdGlvbl91cmkiOiJodHRwczovL3ZlcmlmaWVyL3ZlcmlmaWVyL3ByZXNlbnRhdGlvbl9kZWZpbml0aW9uX3VyaSIsImNsaWVudF9tZXRhZGF0YSI6IntcImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZ1wiOlwiRUNESC1FU1wiLFwiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jXCI6XCJBMjU2R0NNXCIsXCJ2cF9mb3JtYXRzXCI6e1wibXNvX21kb2NcIjp7XCJhbGdcIjpbXCJFUzI1NlwiLFwiRWREU0FcIl19LFwibGRwX3ZwXCI6e1wicHJvb2ZfdHlwZVwiOltcIkVkMjU1MTlTaWduYXR1cmUyMDE4XCIsXCJFZDI1NTE5U2lnbmF0dXJlMjAyMFwiLFwiUnNhU2lnbmF0dXJlMjAxOFwiXX19LFwicmVxdWlyZV9zaWduZWRfcmVxdWVzdF9vYmplY3RcIjp0cnVlfSIsInN0YXRlIjoiYTN3dlBFdXpweW0za0wxZEpMeFk3Zz09Iiwibm9uY2UiOiJJc0JTd2YyNFRCOU00VzBRbHhEbWlnPT0iLCJjbGllbnRfaWQiOiJodHRwczovL3ZlcmlmaWVyIiwiY2xpZW50X2lkX3NjaGVtZSI6ImRpZCIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsInJlc3BvbnNlX3R5cGUiOiJ2cF90b2tlbiIsInJlc3BvbnNlX3VyaSI6Imh0dHBzOi8vdmVyaWZpZXIvdmVyaWZpZXIvdnAtcmVzcG9uc2UifQ"
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://verifier/verifier/get-auth-request-obj",
                any()
            )
        } returns authorizationRequestObjectWithDifferentClientIdSchemeFromAuthorizationRequestParam

        val invalidClientIsSchemeException =
            assertThrows(AuthorizationRequestExceptions.InvalidData::class.java) {
                AuthorizationRequest.validateAndGetAuthorizationRequest(
                    encodedAuthorizationRequestInPreregisteredClientIdScheme,
                    { _: String -> },
                    trustedVerifiers,
                    shouldValidateClient = true
                )
            }

        assertEquals(
            "Client Id scheme mismatch in Authorization Request parameter and the Request Object",
            invalidClientIsSchemeException.message
        )

        val authorizationRequestObjectWithDifferentClientIdFromAuthorizationRequestParam =
            "eyJwcmVzZW50YXRpb25fZGVmaW5pdGlvbl91cmkiOiJodHRwczovL3ZlcmlmaWVyL3ZlcmlmaWVyL3ByZXNlbnRhdGlvbl9kZWZpbml0aW9uX3VyaSIsImNsaWVudF9tZXRhZGF0YSI6IntcImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZ1wiOlwiRUNESC1FU1wiLFwiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jXCI6XCJBMjU2R0NNXCIsXCJ2cF9mb3JtYXRzXCI6e1wibXNvX21kb2NcIjp7XCJhbGdcIjpbXCJFUzI1NlwiLFwiRWREU0FcIl19LFwibGRwX3ZwXCI6e1wicHJvb2ZfdHlwZVwiOltcIkVkMjU1MTlTaWduYXR1cmUyMDE4XCIsXCJFZDI1NTE5U2lnbmF0dXJlMjAyMFwiLFwiUnNhU2lnbmF0dXJlMjAxOFwiXX19LFwicmVxdWlyZV9zaWduZWRfcmVxdWVzdF9vYmplY3RcIjp0cnVlfSIsInN0YXRlIjoiNXpwM0pHdjNqako2R3hKNXJ5OE0vZz09Iiwibm9uY2UiOiJpcG9pVy9yZ3JJNDIvbmltRjVKUm93PT0iLCJjbGllbnRfaWQiOiJodHRwczovL3ZlcmlmaWVyMSIsImNsaWVudF9pZF9zY2hlbWUiOiJwcmUtcmVnaXN0ZXJlZCIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsInJlc3BvbnNlX3R5cGUiOiJ2cF90b2tlbiIsInJlc3BvbnNlX3VyaSI6Imh0dHBzOi8vdmVyaWZpZXIvdmVyaWZpZXIvdnAtcmVzcG9uc2UifQ\n"
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://verifier/verifier/get-auth-request-obj",
                any()
            )
        } returns authorizationRequestObjectWithDifferentClientIdFromAuthorizationRequestParam

        val invalidClientIdException =
            assertThrows(AuthorizationRequestExceptions.InvalidData::class.java) {
                AuthorizationRequest.validateAndGetAuthorizationRequest(
                    encodedAuthorizationRequestInPreregisteredClientIdScheme,
                    { _: String -> },
                    trustedVerifiers,
                    shouldValidateClient = true
                )
            }

        assertEquals(
            "Client Id mismatch in Authorization Request parameter and the Request Object",
            invalidClientIdException.message
        )
    }
*/
    //Client Id scheme - Pre-registered
    @Test
    fun `should validate client_id when authorization request is obtained by reference in pre-registered client id scheme`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://verifier/verifier/get-auth-request-obj",
                any()
            )
        } returns createAuthorizationRequestObject(ClientIdScheme.DID, requestParams + mapOf(
            "client_id" to "wrong-client-id",
            "client_id_scheme" to ClientIdScheme.PRE_REGISTERED.value
        ))

        val authorizationRequestParamsMap = requestParams + mapOf(
            "client_id" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
            "client_id_scheme" to ClientIdScheme.PRE_REGISTERED.value
        )
        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(authorizationRequestParamsMap,true , ClientIdScheme.DID)

        val invalidClientIdException =
            assertThrows(AuthorizationRequestExceptions.InvalidData::class.java) {
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
                "https://verifier/verifier/get-auth-request-obj",
                any()
            )
        } returns createAuthorizationRequestObject(ClientIdScheme.DID, requestParams + mapOf(
            "client_id" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
            "client_id_scheme" to ClientIdScheme.DID.value
        ))

        val authorizationRequestParamsMap = requestParams + mapOf(
            "client_id" to "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
            "client_id_scheme" to ClientIdScheme.PRE_REGISTERED.value
        )
        val encodedAuthorizationRequest =
            createEncodedAuthorizationRequest(authorizationRequestParamsMap,true , ClientIdScheme.DID)

        val invalidClientIsSchemeException =
            assertThrows(AuthorizationRequestExceptions.InvalidData::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest,
                    trustedVerifiers,
                    shouldValidateClient = true
                )
            }

        assertEquals(
            "Client Id scheme mismatch in Authorization Request parameter and the Request Object",
            invalidClientIsSchemeException.message
        )
    }
}

