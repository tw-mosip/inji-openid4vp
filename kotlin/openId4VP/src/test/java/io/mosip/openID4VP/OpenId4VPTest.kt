package io.mosip.openID4VP

import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.dto.Verifier
import org.apache.commons.codec.binary.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import java.nio.charset.StandardCharsets


class OpenId4VPTest {

    private lateinit var openId4VP: OpenId4VP
    private lateinit var trustedVerifiers: List<Verifier>
    private lateinit var state: String
    private lateinit var nonce: String
    private lateinit var presentationDefinition: String
    private lateinit var encodedAuthorizationRequestUrl: String

    @Before
    fun setUp() {
        openId4VP = OpenId4VP("123")
        trustedVerifiers = listOf(Verifier("https://injiverify.dev2.mosip.net", listOf("https://injiverify.qa-inji.mosip.net/redirect", "https://injiverify.dev2.mosip.net/redirect")), Verifier("https://injiverify.dev1.mosip.net",
            listOf( "https://injiverify.qa-inji.mosip.net/redirect","https://injiverify.dev1.mosip.net/redirect")
        ))
        state = "fsnC8ixCs6mWyV+00k23Qg=="
        nonce = "bMHvX1HGhbh8zqlSWf/fuQ=="
        presentationDefinition = "{\"id\":\"vptokenexample\",\"input_descriptors\":[{\"id\":\"idcardcredential\",\"format\":{\"ldp_vc\":{\"proof_type\":[\"Ed25519Signature2018\"]}},\"constraints\":{\"fields\":[{\"path\":[\"$.type\"]}]}}]}"
    }

    private fun createEncodedAuthorizationRequest(clientId: String? = null, presentationDefinition: String?= null, scope: String? = null): String {
        val authorizationRequestUrl = StringBuilder("OPENID4VP://authorize?")
        if (clientId != null) authorizationRequestUrl.append("client_id=$clientId&")
        if (presentationDefinition != null) authorizationRequestUrl.append("presentation_definition=$presentationDefinition&")
        if (scope != null) authorizationRequestUrl.append("scope=$scope&")
        authorizationRequestUrl.append("response_type=vp_token&response_mode=direct_post&nonce=$nonce&state=$state&response_uri=https://injiverify.dev2.mosip.net/redirect")
        val encodedAuthorizationRequestInBytes = Base64.encodeBase64(authorizationRequestUrl.toString().toByteArray(StandardCharsets.UTF_8))
        return String(encodedAuthorizationRequestInBytes,StandardCharsets.UTF_8)
    }

    @Test
    fun shouldThrowErrorIfAnyMandatoryQueryParamIsMissingInReceivedAuthorizationRequest() {
        encodedAuthorizationRequestUrl = createEncodedAuthorizationRequest(presentationDefinition = presentationDefinition)
        val expectedValue = "Missing Input: client_id param is required"

        val missingInputException = assertThrows(AuthorizationRequestExceptions.MissingInput::class.java ){openId4VP.authenticateVerifier(encodedAuthorizationRequestUrl,trustedVerifiers)}
        val actualValue = missingInputException.message

        assertEquals(expectedValue,actualValue)
    }

    @Test
    fun shouldThrowErrorIfBothPresentationDefinitionAndScopeRequestParamsArePresentInAuthorizationRequest(){
        encodedAuthorizationRequestUrl = createEncodedAuthorizationRequest(presentationDefinition=presentationDefinition,scope="sunbird_health_insurance_vc")
        val expectedValue = "Only one of presentation_definition or scope request param can be present"

        val illegalArgumentException = assertThrows(IllegalArgumentException::class.java ){openId4VP.authenticateVerifier(encodedAuthorizationRequestUrl,trustedVerifiers)}
        val actualValue = illegalArgumentException.message

        assertEquals(expectedValue,actualValue)
    }

    @Test
    fun shouldThrowErrorIfBothPresentationDefinitionAndScopeRequestParamsAreNotPresentInAuthorizationRequest(){
        encodedAuthorizationRequestUrl = createEncodedAuthorizationRequest(clientId="https://injiverify.dummy.mosip.net")
        val expectedValue = "Either presentation_definition or scope request param must be present"

        val illegalArgumentException = assertThrows(IllegalArgumentException::class.java ){openId4VP.authenticateVerifier(encodedAuthorizationRequestUrl,trustedVerifiers)}
        val actualValue = illegalArgumentException.message

        assertEquals(expectedValue,actualValue)
    }

    @Test
    fun shouldThrowErrorIfReceivedClientIdIsNotMatchingWithPredefinedListOfVerifiersClientId(){
        encodedAuthorizationRequestUrl = createEncodedAuthorizationRequest(clientId="https://injiverify.dummy.mosip.net",presentationDefinition=presentationDefinition)
        val expectedValue = "VP sharing is stopped as the verifier authentication is failed"

        val invalidClientIdException = assertThrows(AuthorizationRequestExceptions.InvalidVerifierClientIDException::class.java ){openId4VP.authenticateVerifier(encodedAuthorizationRequestUrl,trustedVerifiers)}
        val actualValue = invalidClientIdException.message

        assertEquals(expectedValue,actualValue)
    }


    @Test
    fun shouldReturnAuthenticationResponseIfAllTheFieldsArePresentAndValid(){
        encodedAuthorizationRequestUrl = createEncodedAuthorizationRequest(clientId="https://injiverify.dev2.mosip.net",presentationDefinition=presentationDefinition)
        val expectedValue = mutableMapOf("presentation_definition" to presentationDefinition)

        val actualValue = openId4VP.authenticateVerifier(encodedAuthorizationRequestUrl,trustedVerifiers)
        assertEquals(expectedValue, actualValue)
    }
}