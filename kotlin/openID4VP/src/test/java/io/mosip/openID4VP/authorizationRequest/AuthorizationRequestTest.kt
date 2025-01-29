package io.mosip.openID4VP.authorizationRequest

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.dto.Verifier
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.apache.commons.codec.binary.Base64
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.nio.charset.StandardCharsets
import java.util.concurrent.TimeUnit

class AuthorizationRequestTest {
    private lateinit var openID4VP: OpenID4VP
    private lateinit var trustedVerifiers: List<Verifier>
    private lateinit var presentationDefinition: String
    private lateinit var presentationDefinitionUri: String
    private lateinit var encodedAuthorizationRequestUrl: String
    private lateinit var actualException: Exception
    private lateinit var expectedExceptionMessage: String
    private var shouldValidateClient = true
    private lateinit var mockWebServer: MockWebServer

    @Before
    fun setUp() {
        mockWebServer = MockWebServer()
        mockWebServer.start(8080)

        openID4VP = OpenID4VP("test-OpenID4VP")
        trustedVerifiers = listOf(
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
        presentationDefinition =
            """{"id":"649d581c-f891-4969-9cd5-2c27385a348f","input_descriptors":[{"id":"idcardcredential","format":{"ldp_vc":{"proof_type":["Ed25519Signature2018"]}},"constraints":{"fields":[{"path":["$.type"]}]}}]}"""
        presentationDefinitionUri = "verifier/presentation_definition_uri"
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
        mockWebServer.shutdown()
    }

    @Test
    fun `should throw missing input exception if client_id param is missing in Authorization Request`() {
        encodedAuthorizationRequestUrl =
            createEncodedAuthorizationRequest(
                mapOf("presentation_definition" to presentationDefinition)
            )
        expectedExceptionMessage = "Missing Input: client_id param is required"

        actualException =
            assertThrows(AuthorizationRequestExceptions.MissingInput::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequestUrl, trustedVerifiers, shouldValidateClient
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid input exception if client_id param is present in Authorization Request but it's value is empty string`() {
        encodedAuthorizationRequestUrl =
            createEncodedAuthorizationRequest(
                mapOf("presentation_definition" to presentationDefinition, "client_id" to "")
            )
        expectedExceptionMessage = "Invalid Input: client_id value cannot be an empty string, null, or an integer"

        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidInput::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequestUrl, trustedVerifiers, shouldValidateClient
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid input exception if client_id param is present in Authorization Request but it's value is null`() {
        encodedAuthorizationRequestUrl =
            createEncodedAuthorizationRequest(
                mapOf("presentation_definition" to presentationDefinition, "client_id" to null)
            )
        expectedExceptionMessage = "Invalid Input: client_id value cannot be an empty string, null, or an integer"

        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidInput::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequestUrl, trustedVerifiers, shouldValidateClient
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if neither presentation_definition nor presentation_definition_uri param present in Authorization Request`() {
        encodedAuthorizationRequestUrl =
            createEncodedAuthorizationRequest(mapOf("client_id" to "https://verifier.env1.net"))
        val expectedExceptionMessage =
            "Either presentation_definition or presentation_definition_uri request param must be present"

        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidQueryParams::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequestUrl, trustedVerifiers, shouldValidateClient
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if both presentation_definition and presentation_definition_uri request params are present in Authorization Request`() {
        encodedAuthorizationRequestUrl = createEncodedAuthorizationRequest(
            mapOf(
                "presentation_definition" to presentationDefinition,
                "presentation_definition_uri" to presentationDefinitionUri
            )
        )
        val expectedExceptionMessage =
            "Either presentation_definition or presentation_definition_uri request param can be provided but not both"
        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidQueryParams::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequestUrl, trustedVerifiers, shouldValidateClient
                )
            }
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if received client_id is not matching with predefined Verifiers list client_id`() {
        encodedAuthorizationRequestUrl = createEncodedAuthorizationRequest(
            mapOf(
                "client_id" to "https://verifier.env4.net",
                "client_id_scheme" to "pre-registered",
                "presentation_definition" to presentationDefinition
            )
        )
        val expectedExceptionMessage =
            "VP sharing failed: Verifier authentication was unsuccessful"

        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidVerifierClientID::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequestUrl, trustedVerifiers, shouldValidateClient
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid limit disclosure exception if limit disclosure is present and not matching with predefined values`() {
        presentationDefinition =
            """{"id":"649d581c-f891-4969-9cd5-2c27385a348f","input_descriptors":[{"id":"idcardcredential","constraints":{"fields":[{"path":["$.type"]}], "limit_disclosure": "not preferred"}}]}"""
        encodedAuthorizationRequestUrl = createEncodedAuthorizationRequest(
            mapOf(
                "client_id" to "https://verifier.env1.net",
                "client_id_scheme" to "pre-registered",
                "presentation_definition" to presentationDefinition
            )
        )
        val expectedExceptionMessage =
            "Invalid Input: constraints->limit_disclosure value should be either required or preferred"

        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidLimitDisclosure::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequestUrl, trustedVerifiers, shouldValidateClient
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should return Authorization Request as Authentication Response if presentation_definition & all the other fields are present and valid in Authorization Request`() {
        encodedAuthorizationRequestUrl = createEncodedAuthorizationRequest(
            mapOf(
                "client_id" to "https://verifier.env1.net",
                "client_id_scheme" to "pre-registered",
                "presentation_definition" to presentationDefinition
            )
        )
        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequestUrl, trustedVerifiers, shouldValidateClient)
        assertTrue(actualValue is AuthorizationRequest)
    }

    @Test
    fun `should return Authorization Request as Authentication Response if presentation_definition_uri & all the other fields are present and valid in Authorization Request`() {
        val mockResponse = MockResponse().setResponseCode(200).setBody(presentationDefinition)
        mockWebServer.enqueue(mockResponse)

        encodedAuthorizationRequestUrl = createEncodedAuthorizationRequest(
            mapOf(
                "client_id" to "https://verifier.env1.net",
                "client_id_scheme" to "pre-registered",
                "presentation_definition_uri" to mockWebServer.url(presentationDefinitionUri)
                    .toString()
            )
        )

        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequestUrl, trustedVerifiers, shouldValidateClient)
        assertTrue(actualValue is AuthorizationRequest)
    }

    @Test
    fun `should return Authorization Request as Authentication Response if all the fields are valid in Authorization Request and clientValidation is not needed`() {
        encodedAuthorizationRequestUrl = createEncodedAuthorizationRequest(
            mapOf(
                "client_id" to "https://verifier.env1.net",
                "client_id_scheme" to "pre-registered",
                "presentation_definition" to presentationDefinition
            )
        )
        shouldValidateClient = false

        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequestUrl, trustedVerifiers, shouldValidateClient)
        assertTrue(actualValue is AuthorizationRequest)
    }

    @Test
    fun `should throw missing input exception when client_id_scheme is not available in authorization request query parameter`() {
        encodedAuthorizationRequestUrl = createEncodedAuthorizationRequest(
            mapOf(
                "client_id" to "https://verifier.env1.net",
                "presentation_definition" to presentationDefinition
            )
        )

        val missingInputException =
            assertThrows(AuthorizationRequestExceptions.MissingInput::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequestUrl,
                    trustedVerifiers,
                    true
                )
            }

        assertEquals("Missing Input: client_id_scheme param is required",missingInputException.message)
    }

    // TODO: Group request_uri related tests together
    private val validEncodedAuthorizationRequestWithAuthorizationRequestObjectToBeObtainedByReference =
        "openid4vp://authorize?Y2xpZW50X2lkPWRpZDp3ZWI6YWRpdHlhbmthbm5hbi10dy5naXRodWIuaW86b3BlbmlkNHZwOmZpbGVzJmNsaWVudF9pZF9zY2hlbWU9ZGlkJnJlcXVlc3RfdXJpPWh0dHA6Ly9sb2NhbGhvc3Q6MzAwMC92ZXJpZmllci9nZXQtYXV0aC1yZXF1ZXN0LW9iaiZyZXF1ZXN0X3VyaV9tZXRob2Q9Z2V0IEhUVFAvMS4x"
    private val validAuthorizationRequestObject =
        "eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6d2ViOmFkaXR5YW5rYW5uYW4tdHcuZ2l0aHViLmlvOm9wZW5pZDR2cDpmaWxlcyNrZXktMCJ9.eyJwcmVzZW50YXRpb25fZGVmaW5pdGlvbl91cmkiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvdmVyaWZpZXIvcHJlc2VudGF0aW9uX2RlZmluaXRpb25fdXJpIiwiY2xpZW50X21ldGFkYXRhIjoie1wiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfYWxnXCI6XCJFQ0RILUVTXCIsXCJhdXRob3JpemF0aW9uX2VuY3J5cHRlZF9yZXNwb25zZV9lbmNcIjpcIkEyNTZHQ01cIixcInZwX2Zvcm1hdHNcIjp7XCJtc29fbWRvY1wiOntcImFsZ1wiOltcIkVTMjU2XCIsXCJFZERTQVwiXX0sXCJsZHBfdnBcIjp7XCJwcm9vZl90eXBlXCI6W1wiRWQyNTUxOVNpZ25hdHVyZTIwMThcIixcIkVkMjU1MTlTaWduYXR1cmUyMDIwXCIsXCJSc2FTaWduYXR1cmUyMDE4XCJdfX0sXCJyZXF1aXJlX3NpZ25lZF9yZXF1ZXN0X29iamVjdFwiOnRydWV9Iiwic3RhdGUiOiJXM1hMa0Z5aWNaUFh4UzhkaFpjNGRBPT0iLCJub25jZSI6Im1yT0toNU4rSWNZOXZXK0NpYTdGYVE9PSIsImNsaWVudF9pZCI6ImRpZDp3ZWI6YWRpdHlhbmthbm5hbi10dy5naXRodWIuaW86b3BlbmlkNHZwOmZpbGVzIiwiY2xpZW50X2lkX3NjaGVtZSI6ImRpZCIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsInJlc3BvbnNlX3R5cGUiOiJ2cF90b2tlbiIsInJlc3BvbnNlX3VyaSI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMC92ZXJpZmllci92cC1yZXNwb25zZSJ9.sLrMvak07AfF7KBEhOQZEHkBXlRUiN26RUNZ1stTsuYlvQHnp3CKxpqIQ_V8HllEflt6JaLhZA2wa3uZAQneDQ"

    @Test
    fun `should return Authorization Request if it has request uri and it is a valid authorization request`() {
        mockWebServer.enqueue(
            MockResponse().setResponseCode(200).setBody(validAuthorizationRequestObject)
        )
        encodedAuthorizationRequestUrl = createEncodedAuthorizationRequestForRequestUri()
        shouldValidateClient = true

        val actualValue =
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequestUrl,
                trustedVerifiers,
                shouldValidateClient
            )

        assertTrue(actualValue is AuthorizationRequest)
    }

    @Test
    fun `should validate and return authorization request successfully when the authorization request object is sent by reference by verifier with did client id scheme`() {
        mockWebServer.enqueue(
            MockResponse().setResponseCode(200).setBody(validAuthorizationRequestObject)
        )

        val authorizationRequestObject = openID4VP.authenticateVerifier(
            validEncodedAuthorizationRequestWithAuthorizationRequestObjectToBeObtainedByReference,
            trustedVerifiers,
            shouldValidateClient
        )

        assertTrue(authorizationRequestObject is AuthorizationRequest)
//        assertEquals("AuthorizationRequest(clientId=did:web:adityankannan-tw.github.io:openid4vp:files, clientIdScheme=did, responseType=vp_token, responseMode=direct_post, presentationDefinition=io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition@a49cdd6, responseUri=http://localhost:3000/verifier/vp-response, redirectUri=null, nonce=PDlEG88pJ4/bkLSEqzsyDQ==, state=7gFUwnbrm1Gg+ZnktdkVoA==, clientMetadata=io.mosip.openID4VP.authorizationRequest.ClientMetadata@109a462e)", authorizationRequestObject.toString())
    }

    @Test
    fun `should make call to request_uri with the request_uri_method when the fields are available`() {
        mockWebServer.enqueue(
            MockResponse().setResponseCode(200).setBody(validAuthorizationRequestObject)
        )

        openID4VP.authenticateVerifier(
            validEncodedAuthorizationRequestWithAuthorizationRequestObjectToBeObtainedByReference,
            trustedVerifiers,
            shouldValidateClient
        )
        val request: RecordedRequest? = mockWebServer.takeRequest(5, TimeUnit.SECONDS)

        assertEquals(
            "POST $ HTTP/1.1",
            request?.requestLine ?: ""
        )
    }

    @Test
    fun `should make a call to request_uri in get http call if request_uri_method is not available`() {
        val encodedAuthorizationRequestWithoutRequestUriMethodParameter =
            "openid4vp://authorize?Y2xpZW50X2lkPWRpZDp3ZWI6YWRpdHlhbmthbm5hbi10dy5naXRodWIuaW86b3BlbmlkNHZwOmZpbGVzJmNsaWVudF9pZF9zY2hlbWU9ZGlkJnJlcXVlc3RfdXJpPWh0dHA6Ly9sb2NhbGhvc3Q6MzAwMC92ZXJpZmllci9nZXQtYXV0aC1yZXF1ZXN0LW9iag=="
        mockWebServer.enqueue(
            MockResponse().setResponseCode(200)
                .setBody(encodedAuthorizationRequestWithoutRequestUriMethodParameter)
        )

        openID4VP.authenticateVerifier(
            validEncodedAuthorizationRequestWithAuthorizationRequestObjectToBeObtainedByReference,
            trustedVerifiers,
            shouldValidateClient
        )
        val request: RecordedRequest? = mockWebServer.takeRequest(5, TimeUnit.SECONDS)

        assertEquals(
            "GET $ HTTP/1.1",
            request?.requestLine ?: ""
        )
    }

    @Test
    fun `should throw exception when the client_id validation fails while obtaining Authorization request object by reference`() {
        val authRequest =
            "openid4vp://authorize?Y2xpZW50X2lkPWRpZDp3ZWI6YWRpdHlhbmthbm5hbi10dy5naXRodWIuaW86b3BlbmlkNHZwOmZpbGVzJmNsaWVudF9pZF9zY2hlbWU9ZGlkJnJlcXVlc3RfdXJpPWh0dHA6Ly9sb2NhbGhvc3Q6MzAwMC92ZXJpZmllci9nZXQtYXV0aC1yZXF1ZXN0LW9iaiZyZXF1ZXN0X3VyaV9tZXRob2Q9Z2V0IEhUVFAvMS4x\n"
        val authorizationRequestObjectWithDifferentClientIdFormAuthorizationRequestObject =
            "eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6d2ViOmFkaXR5YW5rYW5uYW4tdHcuZ2l0aHViLmlvOm9wZW5pZDR2cDpmaWxlcyNrZXktMCJ9.eyJwcmVzZW50YXRpb25fZGVmaW5pdGlvbl91cmkiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvdmVyaWZpZXIvcHJlc2VudGF0aW9uX2RlZmluaXRpb25fdXJpIiwiY2xpZW50X21ldGFkYXRhIjoie1wiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfYWxnXCI6XCJFQ0RILUVTXCIsXCJhdXRob3JpemF0aW9uX2VuY3J5cHRlZF9yZXNwb25zZV9lbmNcIjpcIkEyNTZHQ01cIixcInZwX2Zvcm1hdHNcIjp7XCJtc29fbWRvY1wiOntcImFsZ1wiOltcIkVTMjU2XCIsXCJFZERTQVwiXX0sXCJsZHBfdnBcIjp7XCJwcm9vZl90eXBlXCI6W1wiRWQyNTUxOVNpZ25hdHVyZTIwMThcIixcIkVkMjU1MTlTaWduYXR1cmUyMDIwXCIsXCJSc2FTaWduYXR1cmUyMDE4XCJdfX0sXCJyZXF1aXJlX3NpZ25lZF9yZXF1ZXN0X29iamVjdFwiOnRydWV9Iiwic3RhdGUiOiJ4eHgzcTRlMzNITHBZN2FIVmlQRml3PT0iLCJub25jZSI6IkY1Sy95Z0lBOFcwbVhWQ3JjZExBQVE9PSIsImNsaWVudF9pZCI6ImNsaWVudC1tb2NrLTEyMyIsImNsaWVudF9pZF9zY2hlbWUiOiJkaWQiLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJyZXNwb25zZV91cmkiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvdmVyaWZpZXIvdnAtcmVzcG9uc2UifQ.PCC4naTjQM6hiIqFgYWTN50lnxRPLy9OSLyswjssGrJ4v0RTu5y-C5bCMzzWUtjNRbXLVAcOfltGy1yEIpGqAw"
        mockWebServer.enqueue(
            MockResponse().setResponseCode(200).setBody(
                authorizationRequestObjectWithDifferentClientIdFormAuthorizationRequestObject
            )
        )


        val exception = assertThrows(AuthorizationRequestExceptions.InvalidData::class.java) {
            openID4VP.authenticateVerifier(authRequest, trustedVerifiers, shouldValidateClient)
        }

        assertEquals(
            "Client Id mismatch in Authorization Request parameter and the Request Object",
            exception.message
        )
    }

    @Test
    fun `should throw exception when the client_id_scheme validation fails while obtaining Authorization request object by reference`() {
        val authRequest =
            "openid4vp://authorize?Y2xpZW50X2lkPWRpZDp3ZWI6YWRpdHlhbmthbm5hbi10dy5naXRodWIuaW86b3BlbmlkNHZwOmZpbGVzJmNsaWVudF9pZF9zY2hlbWU9ZGlkJnJlcXVlc3RfdXJpPWh0dHA6Ly9sb2NhbGhvc3Q6MzAwMC92ZXJpZmllci9nZXQtYXV0aC1yZXF1ZXN0LW9iaiZyZXF1ZXN0X3VyaV9tZXRob2Q9Z2V0IEhUVFAvMS4x\n"
        val authorizationRequestObjectWithDifferentClientIdSchemeFormAuthorizationRequestObject =
            "eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6d2ViOmFkaXR5YW5rYW5uYW4tdHcuZ2l0aHViLmlvOm9wZW5pZDR2cDpmaWxlcyNrZXktMCJ9.eyJwcmVzZW50YXRpb25fZGVmaW5pdGlvbl91cmkiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvdmVyaWZpZXIvcHJlc2VudGF0aW9uX2RlZmluaXRpb25fdXJpIiwiY2xpZW50X21ldGFkYXRhIjoie1wiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfYWxnXCI6XCJFQ0RILUVTXCIsXCJhdXRob3JpemF0aW9uX2VuY3J5cHRlZF9yZXNwb25zZV9lbmNcIjpcIkEyNTZHQ01cIixcInZwX2Zvcm1hdHNcIjp7XCJtc29fbWRvY1wiOntcImFsZ1wiOltcIkVTMjU2XCIsXCJFZERTQVwiXX0sXCJsZHBfdnBcIjp7XCJwcm9vZl90eXBlXCI6W1wiRWQyNTUxOVNpZ25hdHVyZTIwMThcIixcIkVkMjU1MTlTaWduYXR1cmUyMDIwXCIsXCJSc2FTaWduYXR1cmUyMDE4XCJdfX0sXCJyZXF1aXJlX3NpZ25lZF9yZXF1ZXN0X29iamVjdFwiOnRydWV9Iiwic3RhdGUiOiJkbFkrQU5jNVA0TEd0bldsaUdqa1dBPT0iLCJub25jZSI6Ii9CQW9JeWxFdERVeXRiUjBadDFML2c9PSIsImNsaWVudF9pZCI6ImRpZDp3ZWI6YWRpdHlhbmthbm5hbi10dy5naXRodWIuaW86b3BlbmlkNHZwOmZpbGVzIiwiY2xpZW50X2lkX3NjaGVtZSI6InJlZGlyZWN0X3VyaSIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsInJlc3BvbnNlX3R5cGUiOiJ2cF90b2tlbiIsInJlc3BvbnNlX3VyaSI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMC92ZXJpZmllci92cC1yZXNwb25zZSJ9.a5SZmQO7o67V7dOJHzUMbIQg4AWO9ULF8p0bDJKE667apW01bGy0tN2zIar7MFoUIV5HLMeDGVCUyIo6vPJDBg"
        mockWebServer.enqueue(
            MockResponse().setResponseCode(200).setBody(
                authorizationRequestObjectWithDifferentClientIdSchemeFormAuthorizationRequestObject
            )
        )

        val exception = assertThrows(AuthorizationRequestExceptions.InvalidData::class.java) {
            openID4VP.authenticateVerifier(authRequest, trustedVerifiers, shouldValidateClient)
        }

        assertEquals(
            "Client Id scheme mismatch in Authorization Request parameter and the Request Object",
            exception.message
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

fun createEncodedAuthorizationRequest(
    params: Map<String, String?>,
): String {
    val state = "fsnC8ixCs6mWyV+00k23Qg=="
    val nonce = "bMHvX1HGhbh8zqlSWf/fuQ=="
    val authorizationRequestUrl = StringBuilder("")

    if (params.containsKey("client_id")) authorizationRequestUrl.append("client_id=${params["client_id"]}&")
    if (params.containsKey("client_id_scheme")) authorizationRequestUrl.append("client_id_scheme=${params["client_id_scheme"]}&")
    if (params.containsKey("presentation_definition")) authorizationRequestUrl.append("presentation_definition=${params["presentation_definition"]}&")
    if (params.containsKey("presentation_definition_uri")) authorizationRequestUrl.append("presentation_definition_uri=${params["presentation_definition_uri"]}&")
    val responseUri: String? = if (params.containsKey("response_uri")) {
        params["response_uri"]
    } else {
        "https://verifier.env2.net/responseUri"
    }
    val clientMetadata: String? = if (params.containsKey("client_metadata")) {
        params["client_metadata"]
    } else {
        """{"client_name":"verifier"}"""
    }

    authorizationRequestUrl.append("response_type=vp_token&response_mode=direct_post&nonce=$nonce&state=$state&response_uri=$responseUri&client_metadata=$clientMetadata")
    val encodedAuthorizationRequestInBytes = Base64.encodeBase64(
        authorizationRequestUrl.toString().toByteArray(
            StandardCharsets.UTF_8
        )
    )
    return "openid4vp://authorize?"+String(encodedAuthorizationRequestInBytes, StandardCharsets.UTF_8)
}