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
import org.apache.commons.codec.binary.Base64
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.nio.charset.StandardCharsets

class AuthorizationRequestTest {
    private lateinit var openID4VP: OpenID4VP
    private lateinit var trustedVerifiers: List<Verifier>
    private lateinit var presentationDefinition: String
    private lateinit var presentationDefinitionUri: String
    private lateinit var encodedAuthorizationRequestUrl: String
    private lateinit var actualException: Exception
    private lateinit var expectedExceptionMessage: String

    @Before
    fun setUp() {
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
        presentationDefinition = """{"id":"649d581c-f891-4969-9cd5-2c27385a348f","input_descriptors":[{"id":"idcardcredential","format":{"ldp_vc":{"proof_type":["Ed25519Signature2018"]}},"constraints":{"fields":[{"path":["$.type"]}]}}]}"""
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
    }

    @Test
    fun `should throw missing input exception if client_id param is missing in Authorization Request`() {
        encodedAuthorizationRequestUrl =
            createEncodedAuthorizationRequest(presentationDefinition = presentationDefinition)
        expectedExceptionMessage = "Missing Input: client_id param is required"

        actualException =
            assertThrows(AuthorizationRequestExceptions.MissingInput::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequestUrl, trustedVerifiers
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if neither presentation_definition nor presentation_definition_uri param present in Authorization Request`() {
        encodedAuthorizationRequestUrl =
            createEncodedAuthorizationRequest(clientId = "https://verifier.env1.net")
        val expectedExceptionMessage =
            "Either presentation_definition or presentation_definition_uri request param must be present"

        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidQueryParams::class.java) {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequestUrl, trustedVerifiers
            )
        }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if both presentation_definition and presentation_definition_uri request params are present in Authorization Request`() {
        encodedAuthorizationRequestUrl = createEncodedAuthorizationRequest(
            presentationDefinition = presentationDefinition,
            presentationDefinitionUri = presentationDefinitionUri
        )
        val expectedExceptionMessage =
            "Either presentation_definition or presentation_definition_uri request param can be provided but not both"
        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidQueryParams::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequestUrl, trustedVerifiers
                )
            }
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if received client_id is not matching with predefined Verifiers list client_id`() {
        encodedAuthorizationRequestUrl = createEncodedAuthorizationRequest(
            clientId = "https://verifier.env4.net",
            presentationDefinition = presentationDefinition
        )
        val expectedExceptionMessage =
            "VP sharing failed: Verifier authentication was unsuccessful"

        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidVerifierClientID::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequestUrl, trustedVerifiers
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid limit disclosure exception if limit disclosure is present and not matching with predefined values`() {
        presentationDefinition =
            """{"id":"649d581c-f891-4969-9cd5-2c27385a348f","input_descriptors":[{"id":"idcardcredential","constraints":{"fields":[{"path":["$.type"]}], "limit_disclosure": "not preferred"}}]}"""
        encodedAuthorizationRequestUrl = createEncodedAuthorizationRequest(
            clientId = "https://verifier.env1.net",
            presentationDefinition = presentationDefinition
        )
        val expectedExceptionMessage =
            "Invalid Input: limit_disclosure value should be either required or preferred"

        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidLimitDisclosure::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequestUrl, trustedVerifiers
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should return Authorization Request as Authentication Response if presentation_definition & all the other fields are present and valid in Authorization Request`() {
        encodedAuthorizationRequestUrl = createEncodedAuthorizationRequest(
            clientId = "https://verifier.env1.net",
            presentationDefinition = presentationDefinition
        )

        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequestUrl, trustedVerifiers)
        assertTrue(actualValue is AuthorizationRequest)
    }

    @Test
    fun `should return Authorization Request as Authentication Response if presentation_definition_uri & all the other fields are present and valid in Authorization Request`() {
        val mockWebServer = MockWebServer()
        mockWebServer.start(8080)
        val mockResponse = MockResponse().setResponseCode(200).setBody(presentationDefinition)
        mockWebServer.enqueue(mockResponse)
        encodedAuthorizationRequestUrl = createEncodedAuthorizationRequest(
            clientId = "https://verifier.env1.net",
            presentationDefinitionUri = mockWebServer.url(presentationDefinitionUri).toString()
        )

        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequestUrl, trustedVerifiers)
        assertTrue(actualValue is AuthorizationRequest)
        mockWebServer.shutdown()
    }
}

fun createEncodedAuthorizationRequest(
    clientId: String? = null,
    presentationDefinition: String? = null,
    presentationDefinitionUri: String? = null,
    responseUri: String = "https://verifier.env2.net/responseUri",
    clientMetadata: String = """{"name":"verifier"}"""
): String {
    val state = "fsnC8ixCs6mWyV+00k23Qg=="
    val nonce = "bMHvX1HGhbh8zqlSWf/fuQ=="
    val authorizationRequestUrl = StringBuilder("")

    if (clientId != null) authorizationRequestUrl.append("client_id=$clientId&")
    if (presentationDefinition != null) authorizationRequestUrl.append("presentation_definition=$presentationDefinition&")
    if (presentationDefinitionUri != null) authorizationRequestUrl.append("presentation_definition_uri=$presentationDefinitionUri&")
    authorizationRequestUrl.append("response_type=vp_token&response_mode=direct_post&nonce=$nonce&state=$state&response_uri=$responseUri&client_metadata=$clientMetadata")
    val encodedAuthorizationRequestInBytes = Base64.encodeBase64(
        authorizationRequestUrl.toString().toByteArray(
            StandardCharsets.UTF_8
        )
    )
    return "openid4vp://authorize?"+String(encodedAuthorizationRequestInBytes, StandardCharsets.UTF_8)
}