package io.mosip.openID4VP.authorizationRequest

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions.InvalidData
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions.InvalidInput
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions.InvalidResponseMode
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions.InvalidVerifier
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions.MissingInput
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions.NetworkRequestFailed
import io.mosip.openID4VP.testData.clientIdAndSchemeOfPreRegistered
import io.mosip.openID4VP.testData.clientIdAndSchemeOfReDirectUri
import io.mosip.openID4VP.testData.createAuthorizationRequestObject
import io.mosip.openID4VP.testData.createUrlEncodedData
import io.mosip.openID4VP.testData.presentationDefinitionString
import io.mosip.openID4VP.testData.requestParams
import io.mosip.openID4VP.testData.requestUrl
import io.mosip.openID4VP.testData.trustedVerifiers
import okhttp3.Headers
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Ignore
import org.junit.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows

class AuthorizationRequestTest {
    private lateinit var openID4VP: OpenID4VP
    private lateinit var actualException: Exception
    private lateinit var expectedExceptionMessage: String
    private var shouldValidateClient = true

    @Before
    fun setUp() {

        mockkObject(NetworkManagerClient.Companion)
        openID4VP = OpenID4VP("test-OpenID4VP")

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
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/verifier/get-presentation-definition",
                HTTP_METHOD.GET
            )
        } returns mapOf("body" to presentationDefinitionString)
    }

    @After
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should throw missing input exception if client_id param is missing in Authorization Request`() {
        val authorizationRequestParamsMap = requestParams.minus(CLIENT_ID.value) + mapOf(
            CLIENT_ID_SCHEME.value to ClientIdScheme.DID.value
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.DID)

        expectedExceptionMessage = "Missing Input: client_id param is required"

        actualException =
            assertThrows(MissingInput::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid client id scheme  exception for invalid client id scheme in Authorization Request`() {
        val authorizationRequestParamsMap = requestParams + mapOf(
            CLIENT_ID_SCHEME.value to "wrong-value"
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.DID)

        expectedExceptionMessage = "Given client_id_scheme is not supported"

        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidClientIdScheme::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid input exception if client_id param is present in Authorization Request but it's value is empty string`() {
        val authorizationRequestParamsMap = requestParams + mapOf(
            CLIENT_ID.value to "",
            CLIENT_ID_SCHEME.value to ClientIdScheme.DID.value
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.DID)

        expectedExceptionMessage = "Invalid Input: client_id value cannot be an empty string, null, or an integer"

        actualException =
            assertThrows(InvalidInput::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if neither presentation_definition nor presentation_definition_uri param present in Authorization Request`() {
        val authorizationRequestParamsMap = requestParams.minus(PRESENTATION_DEFINITION.value) + mapOf(
            CLIENT_ID_SCHEME.value to ClientIdScheme.REDIRECT_URI.value
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,
                false,
                ClientIdScheme.REDIRECT_URI,
                isPresentationDefinitionUriPresent = true
            )

        val expectedExceptionMessage =
            "Either presentation_definition or presentation_definition_uri request param must be present"

        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidQueryParams::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if both presentation_definition and presentation_definition_uri request params are present in Authorization Request`() {
        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfPreRegistered
        val applicableFields = listOf(
            CLIENT_ID.value,
            CLIENT_ID_SCHEME.value,
            RESPONSE_MODE.value,
            RESPONSE_URI.value,
            PRESENTATION_DEFINITION.value,
            PRESENTATION_DEFINITION_URI.value,
            RESPONSE_TYPE.value,
            NONCE.value,
            STATE.value,
            CLIENT_METADATA.value
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap, false, ClientIdScheme.PRE_REGISTERED, applicableFields
            )

        val expectedExceptionMessage =
            "Either presentation_definition or presentation_definition_uri request param can be provided but not both"
        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidQueryParams::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
                )
            }
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should take client id scheme as pre-registered if it is absent in authorization request`() {
        val authorizationRequestParamsMap = requestParams + mapOf(
            CLIENT_ID.value to "https://verifier.env1.net",
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap, false, ClientIdScheme.PRE_REGISTERED
            )


        val authorizationRequest = openID4VP.authenticateVerifier(
            encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
        )

        assertEquals(ClientIdScheme.PRE_REGISTERED.value, authorizationRequest.clientIdScheme)
    }

    @Test
    fun `should throw exception if received client_id is not matching with predefined Verifiers list client_id`() {
        val authorizationRequestParamsMap = requestParams + mapOf(
            CLIENT_ID.value to "https://mock-client-id",
            CLIENT_ID_SCHEME.value to ClientIdScheme.PRE_REGISTERED.value
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.PRE_REGISTERED)

        val expectedExceptionMessage =
            "Verifier is not trusted by the wallet"

        actualException =
            assertThrows(InvalidVerifier::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if the url encoded authorization request is invalid`() {

        val encodedAuthorizationRequest ="@#$$#@"

        val expectedExceptionMessage =
            "Exception occurred when extracting the query params from Authorization Request : Index: 1, Size: 1"

        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidQueryParams::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid limit disclosure exception if limit disclosure is present and not matching with predefined values`() {
        val presentationDefinition =
            """{"id":"649d581c-f891-4969-9cd5-2c27385a348f","input_descriptors":[{"id":"idcardcredential","constraints":{"fields":[{"path":["$.type"]}], "limit_disclosure": "not preferred"}}]}"""

        val authorizationRequestParamsMap = requestParams+ clientIdAndSchemeOfReDirectUri + mapOf(
            PRESENTATION_DEFINITION.value to presentationDefinition
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.REDIRECT_URI, isPresentationDefinitionUriPresent = true)

        val expectedExceptionMessage =
            "Invalid Input: constraints->limit_disclosure value should be either required or preferred"

        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidLimitDisclosure::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should return Authorization Request as Authentication Response if presentation_definition & all the other fields are present and valid in Authorization Request`() {
        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfPreRegistered
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.PRE_REGISTERED)

        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient)
        assertTrue(actualValue is AuthorizationRequest)
    }

    @Test
    fun `should throw error when client_id_scheme is redirect_uri and response_mode is absent`() {

        val authorizationRequestParamsMap = requestParams.minus(RESPONSE_MODE.value) + clientIdAndSchemeOfReDirectUri
        val applicableFields = listOf(
            CLIENT_ID.value,
            CLIENT_ID_SCHEME.value,
            REDIRECT_URI.value,
            PRESENTATION_DEFINITION.value,
            RESPONSE_TYPE.value,
            NONCE.value,
            STATE.value,
            CLIENT_METADATA.value,
            RESPONSE_MODE.value
        )
        val expectedExceptionMessage = "Missing Input: response_mode param is required"

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            false,
            ClientIdScheme.REDIRECT_URI,
            applicableFields
        )

        actualException =
        assertThrows(MissingInput::class.java) {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
            )
        }
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw error when client_id_scheme is redirect_uri and redirect_uri and client_id is different`() {
        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfReDirectUri + mapOf(
            CLIENT_ID.value to "wrong-client-id"
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,false , ClientIdScheme.REDIRECT_URI
            )

        val expectedExceptionMessage = "response_uri should be equal to client_id for given client_id_scheme"
        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidVerifierRedirectUri::class.java) {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient
                )
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should return Authorization Request as Authentication Response if presentation_definition_uri & all the other fields are present and valid in Authorization Request`() {


        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfPreRegistered

        val applicableFields =  listOf(
            CLIENT_ID.value,
            CLIENT_ID_SCHEME.value,
            RESPONSE_MODE.value,
            RESPONSE_URI.value,
            PRESENTATION_DEFINITION_URI.value,
            RESPONSE_TYPE.value,
            NONCE.value,
            STATE.value,
            CLIENT_METADATA.value
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,false , ClientIdScheme.PRE_REGISTERED, applicableFields, isPresentationDefinitionUriPresent = true
            )

        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequest, trustedVerifiers, shouldValidateClient)
        assertTrue(actualValue is AuthorizationRequest)
    }

    @Test
    fun `should throw error if presentation_definition_uri is invalid in authorization request`() {
        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfReDirectUri + mapOf(PRESENTATION_DEFINITION_URI.value to "test-data")
        val applicableFields = listOf(
            CLIENT_ID.value,
            CLIENT_ID_SCHEME.value,
            RESPONSE_MODE.value,
            RESPONSE_URI.value,
            PRESENTATION_DEFINITION_URI.value,
            RESPONSE_TYPE.value,
            NONCE.value,
            STATE.value,
            CLIENT_METADATA.value
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,false , ClientIdScheme.REDIRECT_URI, applicableFields, isPresentationDefinitionUriPresent = true
            )

        actualException =
            assertThrows(InvalidData::class.java) {
                openID4VP.authenticateVerifier(encodedAuthorizationRequest, trustedVerifiers, false)
            }

        assertEquals("presentation_definition_uri data is not valid",actualException.message)
    }

    @Test
    fun `should return Authorization Request as Authentication Response if all the fields are valid in Authorization Request and clientValidation is not needed`() {
        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfReDirectUri
        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,false , ClientIdScheme.REDIRECT_URI
            )

        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequest, trustedVerifiers, false)
        assertTrue(actualValue is AuthorizationRequest)
    }

    @Test
    fun `should get presentation definition  by making api call if presentation_definition_uri is present in authorization request`() {
        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfPreRegistered
        val applicationFields =
            listOf(
                CLIENT_ID.value,
                CLIENT_ID_SCHEME.value,
                RESPONSE_MODE.value,
                RESPONSE_URI.value,
                PRESENTATION_DEFINITION_URI.value,
                RESPONSE_TYPE.value,
                NONCE.value,
                STATE.value,
                CLIENT_METADATA.value
            )
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/json").build(),
            "body" to createAuthorizationRequestObject(ClientIdScheme.PRE_REGISTERED, authorizationRequestParamsMap, applicationFields)
        )


        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.PRE_REGISTERED, applicationFields, true)

        assertDoesNotThrow {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }

    }

    @Test
    fun `should return Authorization Request for redirect uri scheme when passed by value`() {
        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfReDirectUri

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.REDIRECT_URI,)

        assertDoesNotThrow {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }
    }

    @Test
    fun `should throw error if response mode is not present in the authorization request`() {
        val authorizationRequestParamsMap = requestParams.minus(RESPONSE_MODE.value) + clientIdAndSchemeOfReDirectUri

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.REDIRECT_URI,)

        expectedExceptionMessage = "Missing Input: response_mode param is required"
        actualException = assertThrows<MissingInput> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw error if response mode is not valid in the authorization request`() {
        val authorizationRequestParamsMap = requestParams+ clientIdAndSchemeOfReDirectUri + mapOf(RESPONSE_MODE.value to "wrong input")

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.REDIRECT_URI,)

        expectedExceptionMessage = "Given response_mode is not supported"
        actualException = assertThrows<InvalidResponseMode> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw error if redirect uri field is present in the authorization request`() {
        val authorizationRequestParamsMap = requestParams+ clientIdAndSchemeOfReDirectUri + mapOf(REDIRECT_URI.value to "wrong input")

        val applicableFields = listOf(
            CLIENT_ID.value,
            CLIENT_ID_SCHEME.value,
            RESPONSE_MODE.value,
            RESPONSE_URI.value,
            RESPONSE_TYPE.value,
            NONCE.value,
            STATE.value,
            CLIENT_METADATA.value,
            REDIRECT_URI.value
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.REDIRECT_URI,applicableFields)

        expectedExceptionMessage = "redirect_uri should not be present for given response_mode"
        actualException = assertThrows<InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw error if api call of presentation_definition_uri fails in authorization request`() {
        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfPreRegistered + mapOf(PRESENTATION_DEFINITION_URI.value to "https://mock-verifier.com/verifier/get-presentation-definition-1")
        val applicationFields =
            listOf(
                CLIENT_ID.value,
                CLIENT_ID_SCHEME.value,
                RESPONSE_MODE.value,
                RESPONSE_URI.value,
                PRESENTATION_DEFINITION_URI.value,
                RESPONSE_TYPE.value,
                NONCE.value,
                STATE.value,
                CLIENT_METADATA.value
            )
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/json").build(),
            "body" to createAuthorizationRequestObject(ClientIdScheme.PRE_REGISTERED, authorizationRequestParamsMap, applicationFields, isPresentationDefinitionUriPresent = true)
        )


        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.PRE_REGISTERED, applicationFields, isPresentationDefinitionUriPresent = true)

        assertThrows<NetworkRequestFailed> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                trustedVerifiers,
                shouldValidateClient = true
            )
        }
    }

    @Test
    fun `should throw error client id is not present in trusted verifier for pre registered client id scheme in authorization request`() {
        val authorizationRequestParamsMap = requestParams + clientIdAndSchemeOfPreRegistered
        val applicationFields =
            listOf(
                CLIENT_ID.value,
                CLIENT_ID_SCHEME.value,
                RESPONSE_MODE.value,
                RESPONSE_URI.value,
                PRESENTATION_DEFINITION_URI.value,
                RESPONSE_TYPE.value,
                NONCE.value,
                STATE.value,
                CLIENT_METADATA.value
            )
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/json").build(),
            "body" to createAuthorizationRequestObject(ClientIdScheme.PRE_REGISTERED, authorizationRequestParamsMap, applicationFields, isPresentationDefinitionUriPresent = true)
        )


        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , ClientIdScheme.PRE_REGISTERED, applicationFields, isPresentationDefinitionUriPresent = true)

        assertThrows<InvalidVerifier> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
                emptyList(),
                shouldValidateClient = true
            )
        }
    }

}

