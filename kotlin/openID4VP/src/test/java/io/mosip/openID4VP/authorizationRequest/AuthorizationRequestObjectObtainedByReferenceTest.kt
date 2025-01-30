package io.mosip.openID4VP.authorizationRequest

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.verify
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions
import org.apache.commons.codec.binary.Base64
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertDoesNotThrow
import java.nio.charset.StandardCharsets

class AuthorizationRequestObjectObtainedByReference {
    private lateinit var openID4VP: OpenID4VP

    private val trustedVerifiers: List<Verifier> = listOf(
        Verifier(
            "https://verifier.env1.net", listOf(
                "https://verifier.env1.net/responseUri", "https://verifier.env2.net/responseUri"
            )
        ), Verifier(
            "https://verifier.env2.net", listOf(
                "https://verifier.env3.net/responseUri", "https://verifier.env2.net/responseUri"
            )
        )
    )
    private val presentationDefinition =
        """{"id":"649d581c-f891-4969-9cd5-2c27385a348f","input_descriptors":[{"id":"idcardcredential","format":{"ldp_vc":{"proof_type":["Ed25519Signature2018"]}},"constraints":{"fields":[{"path":["$.type"]}]}}]}"""

    private val encodedAuthorizationRequestInDidClientIdScheme =
        "openid4vp://authorize?Y2xpZW50X2lkPWRpZDp3ZWI6YWRpdHlhbmthbm5hbi10dy5naXRodWIuaW86b3BlbmlkNHZwOmZpbGVzJmNsaWVudF9pZF9zY2hlbWU9ZGlkJnJlcXVlc3RfdXJpPWh0dHBzOi8vdmVyaWZpZXIvdmVyaWZpZXIvZ2V0LWF1dGgtcmVxdWVzdC1vYmo=\n"
    private val validAuthorizationRequestObjectInDidClientIdScheme =
        "eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6d2ViOmFkaXR5YW5rYW5uYW4tdHcuZ2l0aHViLmlvOm9wZW5pZDR2cDpmaWxlcyNrZXktMCJ9.eyJwcmVzZW50YXRpb25fZGVmaW5pdGlvbl91cmkiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvdmVyaWZpZXIvcHJlc2VudGF0aW9uX2RlZmluaXRpb25fdXJpIiwiY2xpZW50X21ldGFkYXRhIjoie1wiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfYWxnXCI6XCJFQ0RILUVTXCIsXCJhdXRob3JpemF0aW9uX2VuY3J5cHRlZF9yZXNwb25zZV9lbmNcIjpcIkEyNTZHQ01cIixcInZwX2Zvcm1hdHNcIjp7XCJtc29fbWRvY1wiOntcImFsZ1wiOltcIkVTMjU2XCIsXCJFZERTQVwiXX0sXCJsZHBfdnBcIjp7XCJwcm9vZl90eXBlXCI6W1wiRWQyNTUxOVNpZ25hdHVyZTIwMThcIixcIkVkMjU1MTlTaWduYXR1cmUyMDIwXCIsXCJSc2FTaWduYXR1cmUyMDE4XCJdfX0sXCJyZXF1aXJlX3NpZ25lZF9yZXF1ZXN0X29iamVjdFwiOnRydWV9Iiwic3RhdGUiOiJXM1hMa0Z5aWNaUFh4UzhkaFpjNGRBPT0iLCJub25jZSI6Im1yT0toNU4rSWNZOXZXK0NpYTdGYVE9PSIsImNsaWVudF9pZCI6ImRpZDp3ZWI6YWRpdHlhbmthbm5hbi10dy5naXRodWIuaW86b3BlbmlkNHZwOmZpbGVzIiwiY2xpZW50X2lkX3NjaGVtZSI6ImRpZCIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsInJlc3BvbnNlX3R5cGUiOiJ2cF90b2tlbiIsInJlc3BvbnNlX3VyaSI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMC92ZXJpZmllci92cC1yZXNwb25zZSJ9.sLrMvak07AfF7KBEhOQZEHkBXlRUiN26RUNZ1stTsuYlvQHnp3CKxpqIQ_V8HllEflt6JaLhZA2wa3uZAQneDQ"
    private val didResponse =
        "{\"@context\":\"https://w3id.org/did-resolution/v1\",\"didDocument\":{\"assertionMethod\":[\"did:web:adityankannan-tw.github.io:openid4vp:files#key-0\"],\"service\":[],\"id\":\"did:web:adityankannan-tw.github.io:openid4vp:files\",\"verificationMethod\":[{\"publicKeyMultibase\":\"IKXhA7W1HD1sAl+OfG59VKAqciWrrOL1Rw5F+PGLhi4=\",\"controller\":\"did:web:adityankannan-tw.github.io:openid4vp:files\",\"id\":\"did:web:adityankannan-tw.github.io:openid4vp:files#key-0\",\"type\":\"Ed25519VerificationKey2020\",\"@context\":\"https://w3id.org/security/suites/ed25519-2020/v1\"}],\"@context\":[\"https://www.w3.org/ns/did/v1\"],\"alsoKnownAs\":[],\"authentication\":[\"did:web:adityankannan-tw.github.io:openid4vp:files#key-0\"]},\"didResolutionMetadata\":{\"driverDuration\":19,\"contentType\":\"application/did+ld+json\",\"pattern\":\"^(did:web:.+)\$\",\"driverUrl\":\"http://uni-resolver-driver-did-uport:8081/1.0/identifiers/\",\"duration\":19,\"did\":{\"didString\":\"did:web:adityankannan-tw.github.io:openid4vp:files\",\"methodSpecificId\":\"adityankannan-tw.github.io:openid4vp:files\",\"method\":\"web\"},\"didUrl\":{\"path\":null,\"fragment\":null,\"query\":null,\"didUrlString\":\"did:web:adityankannan-tw.github.io:openid4vp:files\",\"parameters\":null,\"did\":{\"didString\":\"did:web:adityankannan-tw.github.io:openid4vp:files\",\"methodSpecificId\":\"adityankannan-tw.github.io:openid4vp:files\",\"method\":\"web\"}}},\"didDocumentMetadata\":{}}"

    private val encodedAuthorizationRequestInPreregisteredClientIdScheme =
        "openid4vp://authorize?Y2xpZW50X2lkPWh0dHBzOi8vdmVyaWZpZXImY2xpZW50X2lkX3NjaGVtZT1wcmUtcmVnaXN0ZXJlZCZyZXF1ZXN0X3VyaT1odHRwczovL3ZlcmlmaWVyL3ZlcmlmaWVyL2dldC1hdXRoLXJlcXVlc3Qtb2Jq"

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
                "https://resolver.identity.foundation/1.0/identifiers/did:web:adityankannan-tw.github.io:openid4vp:files",
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
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://verifier/verifier/get-auth-request-obj",
                any()
            )
        } returns validAuthorizationRequestObjectInDidClientIdScheme
        val encodedAuthorizationRequestWithRequestUriSupport =
            createEncodedAuthorizationRequestForRequestUri()

        assertDoesNotThrow {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequestWithRequestUriSupport,
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

        val exceptionWhenRequestUriNetworkCallFails = assertThrows(Exception::class.java) {
            AuthorizationRequest.validateAndGetAuthorizationRequest(
                encodedAuthorizationRequestInDidClientIdScheme,
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
        val encodedAuthorizationRequestWithRequestUriMethodParameter =
            "openid4vp://authorize?Y2xpZW50X2lkPWRpZDp3ZWI6YWRpdHlhbmthbm5hbi10dy5naXRodWIuaW86b3BlbmlkNHZwOmZpbGVzJmNsaWVudF9pZF9zY2hlbWU9ZGlkJnJlcXVlc3RfdXJpPWh0dHBzOi8vdmVyaWZpZXIvdmVyaWZpZXIvZ2V0LWF1dGgtcmVxdWVzdC1vYmomcmVxdWVzdF91cmlfbWV0aG9kPXBvc3Q="
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://verifier/verifier/get-auth-request-obj",
                HTTP_METHOD.POST
            )
        } returns validAuthorizationRequestObjectInDidClientIdScheme

        openID4VP.authenticateVerifier(
            encodedAuthorizationRequestWithRequestUriMethodParameter,
            trustedVerifiers,
            shouldValidateClient = true
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                "https://verifier/verifier/get-auth-request-obj",
                HTTP_METHOD.POST
            )
        }
    }

    @Test
    fun `should make a call to request_uri in get http call if request_uri_method is not available in did client id scheme`() {
        val encodedAuthorizationRequestWithoutRequestUriMethodParameter =
            "openid4vp://authorize?Y2xpZW50X2lkPWRpZDp3ZWI6YWRpdHlhbmthbm5hbi10dy5naXRodWIuaW86b3BlbmlkNHZwOmZpbGVzJmNsaWVudF9pZF9zY2hlbWU9ZGlkJnJlcXVlc3RfdXJpPWh0dHBzOi8vdmVyaWZpZXIvdmVyaWZpZXIvZ2V0LWF1dGgtcmVxdWVzdC1vYmo=\n"
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://verifier/verifier/get-auth-request-obj",
                HTTP_METHOD.GET
            )
        } returns validAuthorizationRequestObjectInDidClientIdScheme

        openID4VP.authenticateVerifier(
            encodedAuthorizationRequestWithoutRequestUriMethodParameter,
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
        val authorizationRequestObjectWithDifferentClientIdFormAuthorizationRequestObject =
            "eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6d2ViOmFkaXR5YW5rYW5uYW4tdHcuZ2l0aHViLmlvOm9wZW5pZDR2cDpmaWxlcyNrZXktMCJ9.eyJwcmVzZW50YXRpb25fZGVmaW5pdGlvbl91cmkiOiJodHRwczovL3ZlcmlmaWVyL3ZlcmlmaWVyL3ByZXNlbnRhdGlvbl9kZWZpbml0aW9uX3VyaSIsImNsaWVudF9tZXRhZGF0YSI6IntcImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZ1wiOlwiRUNESC1FU1wiLFwiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jXCI6XCJBMjU2R0NNXCIsXCJ2cF9mb3JtYXRzXCI6e1wibXNvX21kb2NcIjp7XCJhbGdcIjpbXCJFUzI1NlwiLFwiRWREU0FcIl19LFwibGRwX3ZwXCI6e1wicHJvb2ZfdHlwZVwiOltcIkVkMjU1MTlTaWduYXR1cmUyMDE4XCIsXCJFZDI1NTE5U2lnbmF0dXJlMjAyMFwiLFwiUnNhU2lnbmF0dXJlMjAxOFwiXX19LFwicmVxdWlyZV9zaWduZWRfcmVxdWVzdF9vYmplY3RcIjp0cnVlfSIsInN0YXRlIjoidHo0WTBaNEtibWhyYm9FcjJMVWxJZz09Iiwibm9uY2UiOiJFdW9YdW4vc0ZaTlg1WXZGd01mbGFRPT0iLCJjbGllbnRfaWQiOiJtb2NrLWNsaWVudCIsImNsaWVudF9pZF9zY2hlbWUiOiJkaWQiLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJyZXNwb25zZV91cmkiOiJodHRwczovL3ZlcmlmaWVyL3ZlcmlmaWVyL3ZwLXJlc3BvbnNlIn0.I5zfI6TIH-sKTNw0oja6ObyJLYtHh7ioowpt8kJNW8m2g4dp--E6S1US2mifSih-yKOJpRFLTCiIdM4lCyMXCQ"
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://verifier/verifier/get-auth-request-obj",
                any()
            )
        } returns authorizationRequestObjectWithDifferentClientIdFormAuthorizationRequestObject

        val exception = assertThrows(AuthorizationRequestExceptions.InvalidData::class.java) {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequestInDidClientIdScheme,
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
        val authorizationRequestObjectWithDifferentClientIdSchemeFormAuthorizationRequestObject =
            "eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6d2ViOmFkaXR5YW5rYW5uYW4tdHcuZ2l0aHViLmlvOm9wZW5pZDR2cDpmaWxlcyNrZXktMCJ9.eyJwcmVzZW50YXRpb25fZGVmaW5pdGlvbl91cmkiOiJodHRwczovL3ZlcmlmaWVyL3ZlcmlmaWVyL3ByZXNlbnRhdGlvbl9kZWZpbml0aW9uX3VyaSIsImNsaWVudF9tZXRhZGF0YSI6IntcImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZ1wiOlwiRUNESC1FU1wiLFwiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jXCI6XCJBMjU2R0NNXCIsXCJ2cF9mb3JtYXRzXCI6e1wibXNvX21kb2NcIjp7XCJhbGdcIjpbXCJFUzI1NlwiLFwiRWREU0FcIl19LFwibGRwX3ZwXCI6e1wicHJvb2ZfdHlwZVwiOltcIkVkMjU1MTlTaWduYXR1cmUyMDE4XCIsXCJFZDI1NTE5U2lnbmF0dXJlMjAyMFwiLFwiUnNhU2lnbmF0dXJlMjAxOFwiXX19LFwicmVxdWlyZV9zaWduZWRfcmVxdWVzdF9vYmplY3RcIjp0cnVlfSIsInN0YXRlIjoiMFpqNkx1K1IyUExTd0lDRWYxdVBKUT09Iiwibm9uY2UiOiJiUVJIaER3MDNJR081TEZFMHJNazR3PT0iLCJjbGllbnRfaWQiOiJkaWQ6d2ViOmFkaXR5YW5rYW5uYW4tdHcuZ2l0aHViLmlvOm9wZW5pZDR2cDpmaWxlcyIsImNsaWVudF9pZF9zY2hlbWUiOiJwcmUtcmVnaXN0ZXJlZCIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsInJlc3BvbnNlX3R5cGUiOiJ2cF90b2tlbiIsInJlc3BvbnNlX3VyaSI6Imh0dHBzOi8vdmVyaWZpZXIvdmVyaWZpZXIvdnAtcmVzcG9uc2UifQ.vTACb4PA6qsrZgK-6qDU3pAkW703gIs-V-JxeOjocPjqHmy_aL0aSohzmp_piijbVPNqRrP4sbpMobBvwOkWCw"
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://verifier/verifier/get-auth-request-obj",
                any()
            )
        } returns authorizationRequestObjectWithDifferentClientIdSchemeFormAuthorizationRequestObject

        val exception = assertThrows(AuthorizationRequestExceptions.InvalidData::class.java) {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequestInDidClientIdScheme,
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
        val authorizationRequestObjectInBase64 =
            "eyJwcmVzZW50YXRpb25fZGVmaW5pdGlvbl91cmkiOiJodHRwczovL3ZlcmlmaWVyL3ZlcmlmaWVyL3ByZXNlbnRhdGlvbl9kZWZpbml0aW9uX3VyaSIsImNsaWVudF9tZXRhZGF0YSI6IntcImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZ1wiOlwiRUNESC1FU1wiLFwiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jXCI6XCJBMjU2R0NNXCIsXCJ2cF9mb3JtYXRzXCI6e1wibXNvX21kb2NcIjp7XCJhbGdcIjpbXCJFUzI1NlwiLFwiRWREU0FcIl19LFwibGRwX3ZwXCI6e1wicHJvb2ZfdHlwZVwiOltcIkVkMjU1MTlTaWduYXR1cmUyMDE4XCIsXCJFZDI1NTE5U2lnbmF0dXJlMjAyMFwiLFwiUnNhU2lnbmF0dXJlMjAxOFwiXX19LFwicmVxdWlyZV9zaWduZWRfcmVxdWVzdF9vYmplY3RcIjp0cnVlfSIsInN0YXRlIjoidWNQc2pEc3pBdStCc2IzeFFLTi9SZz09Iiwibm9uY2UiOiJEV3JHM2RCSFp0cjZxYjh2MWJzajhRPT0iLCJjbGllbnRfaWQiOiJodHRwczovL3ZlcmlmaWVyIiwiY2xpZW50X2lkX3NjaGVtZSI6InByZS1yZWdpc3RlcmVkIiwicmVzcG9uc2VfbW9kZSI6ImRpcmVjdF9wb3N0IiwicmVzcG9uc2VfdHlwZSI6InZwX3Rva2VuIiwicmVzcG9uc2VfdXJpIjoiaHR0cHM6Ly92ZXJpZmllci92ZXJpZmllci92cC1yZXNwb25zZSJ9"
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://verifier/verifier/get-auth-request-obj",
                HTTP_METHOD.GET
            )
        } returns authorizationRequestObjectInBase64

        assertDoesNotThrow {
            AuthorizationRequest.validateAndGetAuthorizationRequest(
                encodedAuthorizationRequestInPreregisteredClientIdScheme,
                { _: String -> },
                trustedVerifiers,
                false
            )
        }
    }

    @Test
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
}

fun createEncodedAuthorizationRequestForRequestUri(
): String {
    val authorizationRequestUrl = StringBuilder("")

    val baseUrl = "https://verifier"
    val requestUri = "${baseUrl}/verifier/get-auth-request-obj"
    authorizationRequestUrl.append("client_id=did:web:adityankannan-tw.github.io:openid4vp:files&client_id_scheme=did&request_uri=${requestUri}&request_uri_method=get HTTP/1.1")
    val encodedAuthorizationRequestInBytes = Base64.encodeBase64(
        authorizationRequestUrl.toString().toByteArray(
            StandardCharsets.UTF_8
        )
    )
    return "openid4vp://authorize?" + String(
        encodedAuthorizationRequestInBytes,
        StandardCharsets.UTF_8
    )
}
