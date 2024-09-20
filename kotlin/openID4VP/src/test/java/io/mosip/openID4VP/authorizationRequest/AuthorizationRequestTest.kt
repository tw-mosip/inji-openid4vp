package io.mosip.openID4VP.authorizationRequest

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.dto.Verifier
import org.apache.commons.codec.binary.Base64
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import java.nio.charset.StandardCharsets

class AuthorizationRequestTests {
    private lateinit var openID4VP: OpenID4VP
    private lateinit var trustedVerifiers: List<Verifier>
    private lateinit var presentationDefinition: String
    private lateinit var encodedAuthorizationRequestUrl: String
    private lateinit var actualException: Exception
    private lateinit var expectedExceptionMessage: String

    @Before
    fun setUp() {
        openID4VP = OpenID4VP("test-OpenID4VP")
        trustedVerifiers = listOf(
            Verifier(
                "https://verify.env1.net", listOf(
                    "https://verify.env1.net/responseUri",
                    "https://verify.env2.net/responseUri"
                )
            ), Verifier(
                "https://verify.env2.net", listOf(
                    "https://verify.env3.net/responseUri",
                    "https://verify.env2.net/responseUri"
                )
            )
        )
        presentationDefinition =
            "{\"id\":\"649d581c-f891-4969-9cd5-2c27385a348f\",\"input_descriptors\":[{\"id\":\"idcardcredential\",\"constraints\":{\"fields\":[{\"path\":[\"$.type\"]}]}}]}"
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
    fun `should throw missing input exception if client_id is missing`() {
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
    fun `should throw exception if both presentation_definition and scope request params are present in Authorization Request`() {
        encodedAuthorizationRequestUrl = createEncodedAuthorizationRequest(
            presentationDefinition = presentationDefinition, scope = "health_insurance_vc"
        )
        val expectedExceptionMessage =
            "Only one of presentation_definition or scope request param can be present"

        actualException = assertThrows(AuthorizationRequestExceptions.InvalidQueryParams::class.java) {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequestUrl, trustedVerifiers
            )
        }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if both presentation_definition and scope request params are not present in Authorization Request`() {
        encodedAuthorizationRequestUrl =
            createEncodedAuthorizationRequest(clientId = "https://injiverify.dev2.mosip.net")
        val expectedExceptionMessage =
            "Either presentation_definition or scope request param must be present"

        actualException = assertThrows(AuthorizationRequestExceptions.InvalidQueryParams::class.java) {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequestUrl, trustedVerifiers
            )
        }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if received client_id is not matching with predefined Verifiers list client_id`() {
        encodedAuthorizationRequestUrl = createEncodedAuthorizationRequest(
            clientId = "https://verify.env4.net",
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
            "{\"id\":\"649d581c-f891-4969-9cd5-2c27385a348f\",\"input_descriptors\":[{\"id\":\"idcardcredential\",\"constraints\":{\"fields\":[{\"path\":[\"$.type\"]}], \"limit_disclosure\": \"not preferred\"}}]}"
        encodedAuthorizationRequestUrl = createEncodedAuthorizationRequest(
            clientId = "https://verify.env1.net",
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
    fun `should return Authentication Response if all the fields are present and valid in Authorization Request`() {
        encodedAuthorizationRequestUrl = createEncodedAuthorizationRequest(
            clientId = "https://verify.env1.net",
            presentationDefinition = presentationDefinition
        )
        val expectedValue = mutableMapOf("presentation_definition" to presentationDefinition)

        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequestUrl, trustedVerifiers)
        assertEquals(expectedValue, actualValue)
    }
}

fun createEncodedAuthorizationRequest(
    clientId: String? = null,
    presentationDefinition: String? = null,
    scope: String? = null,
    responseUri: String = "https://verify.env2.net/responseUri"
): String {
    val state = "fsnC8ixCs6mWyV+00k23Qg=="
    val nonce = "bMHvX1HGhbh8zqlSWf/fuQ=="
    val authorizationRequestUrl = StringBuilder("")

    if (clientId != null) authorizationRequestUrl.append("client_id=$clientId&")
    if (presentationDefinition != null) authorizationRequestUrl.append("presentation_definition=$presentationDefinition&")
    if (scope != null) authorizationRequestUrl.append("scope=$scope&")
    authorizationRequestUrl.append("response_type=vp_token&response_mode=direct_post&nonce=$nonce&state=$state&response_uri=$responseUri")
    val encodedAuthorizationRequestInBytes = Base64.encodeBase64(
        authorizationRequestUrl.toString().toByteArray(
            StandardCharsets.UTF_8
        )
    )
    return "INJI_OVP://authorize?"+String(encodedAuthorizationRequestInBytes, StandardCharsets.UTF_8)
}