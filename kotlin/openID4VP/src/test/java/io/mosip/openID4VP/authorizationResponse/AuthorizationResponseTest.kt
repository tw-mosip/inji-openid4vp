package io.mosip.openID4VP.authorizationResponse

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.dto.vpResponseMetadata.types.LdpVPResponseMetadata
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions.NetworkRequestFailed
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions.NetworkRequestTimeout
import io.mosip.openID4VP.testData.authorizationResponse
import io.mosip.openID4VP.testData.presentationSubmission
import io.mosip.openID4VP.testData.publicKey
import io.mosip.openID4VP.testData.setField
import io.mosip.openID4VP.testData.vpResponsesMetadata
import io.mosip.openID4VP.testData.vpToken
import io.mosip.openID4VP.testData.vpTokensForSigning
import okhttp3.Headers
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import io.mosip.openID4VP.constants.FormatType

class AuthorizationResponseTest {
    private lateinit var openID4VP: OpenID4VP
    private val selectedCredentialsList = mapOf(
        "456" to mapOf(
            FormatType.LDP_VC to listOf(
                """credential1""",
                """credential2"""
            )
        ), "789" to mapOf(
            FormatType.LDP_VC to listOf(
                """credential3"""
            )
        )
    )
    private lateinit var presentationDefinition: String
    private lateinit var clientMetadata: String
    private lateinit var mockWebServer: MockWebServer
    private lateinit var actualException: Exception
    private lateinit var expectedExceptionMessage: String

    @Before
    fun setUp() {
        mockkObject(NetworkManagerClient)
        openID4VP = OpenID4VP("test-OpenID4VP")
        presentationDefinition =
            """{"id":"649d581c-f891-4969-9cd5-2c27385a348f","input_descriptors":[{"id":"id_123","format":{"ldp_vc":{"proof_type":["Ed25519Signature2018"]}},"constraints":{"fields":[{"path":["$.type"]}]}}]}"""
        clientMetadata = "{\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"ES256\",\"EdDSA\"]},\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\",\"RsaSignature2018\"]}}}"
        mockWebServer = MockWebServer()
        mockWebServer.start(8080)
        openID4VP.authorizationRequest = AuthorizationRequest(
            clientId = "https://injiverify.dev2.mosip.net",
            responseType = "vp_token",
            responseMode = "direct_post",
            presentationDefinition = deserializeAndValidate(
                presentationDefinition,
                PresentationDefinitionSerializer
            ),
            nonce = "bMHvX1HGhbh8zqlSWf/fuQ==",
            state = "fsnC8ixCs6mWyV+00k23Qg==",
            responseUri = "http://mock-verifier.net/response-uri",
            clientMetadata = deserializeAndValidate(clientMetadata, ClientMetadataSerializer),
            clientIdScheme = "redirect_uri",
            redirectUri = null
        )
        setField(
            openID4VP,
            "responseUri",
            "https://mock-verifier.com/response-uri"
        )


        mockkStatic(Log::class)
        every { Log.e(any(), any()) } answers {
            val tag = arg<String>(0)
            val msg = arg<String>(1)
            println("Error: logTag: $tag | Message: $msg")
            0
        }

        openID4VP.constructVerifiablePresentationToken(selectedCredentialsList)
    }

    @After
    fun tearDown() {
        clearAllMocks()
        mockWebServer.shutdown()
    }

    @Test
    fun `should construct VPToken in JsonString format using received selected verifiable credentials`() {
        mockkObject(UUIDGenerator)
        every { UUIDGenerator.generateUUID() } returns "649d581c-f291-4969-9cd5-2c27385a348f"

        val actualValue = openID4VP.constructVerifiablePresentationToken(selectedCredentialsList)

        val expectedVPTokenForSigning = vpTokensForSigning
        assertEquals(
            expectedVPTokenForSigning, actualValue
        )
    }

    @Test
    fun `should throw invalid input exception if any input param of VPResponseMetadata class is empty`() {
        val ldpVpResponseMetadata = LdpVPResponseMetadata(
            "eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ", "RsaSignature2018", publicKey, ""
        )
        val vpResponsesMetadata = mapOf(FormatType.LDP_VC to ldpVpResponseMetadata)
        expectedExceptionMessage = "Invalid Input: vp_response_metadata->domain value cannot be an empty string, null, or an integer"
        actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidInput::class.java) {
                openID4VP.shareVerifiablePresentation(vpResponsesMetadata)
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if Authorization Response request call returns the response with http status other than 200`() {
        every {
            NetworkManagerClient.sendHTTPRequest("https://mock-verifier.com/response-uri", any(), any(), any())
        }  throws NetworkRequestFailed("Unknown error encountered")
        expectedExceptionMessage = "Network request failed with error response - Unknown error encountered"

        actualException =
            assertThrows(NetworkRequestFailed::class.java) {
                openID4VP.shareVerifiablePresentation(vpResponsesMetadata)
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if Authorization Response request call takes more time to return response than specified time`() {
        every {
            NetworkManagerClient.sendHTTPRequest("https://mock-verifier.com/response-uri", any(), any(), any())
        }  throws NetworkRequestTimeout()
        expectedExceptionMessage = "VP sharing failed due to connection timeout"

        actualException =
            assertThrows(NetworkRequestTimeout::class.java) {
                openID4VP.shareVerifiablePresentation(vpResponsesMetadata)
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should get response if Verifiable Presentation is shared successfully to the Verifier`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/response-uri",
                any(),
                any(),
                any()
            )
        } returns mapOf(
            "header" to Headers.Builder().add("content-type", "application/json").build(),
            "body" to "Verifiable Presentation is shared successfully"
        )
        val expectedValue = "Verifiable Presentation is shared successfully"

        val actualResponse = openID4VP.shareVerifiablePresentation(vpResponsesMetadata)

        assertEquals(expectedValue, actualResponse)
    }

    @Test
    fun `should create encodedJsonMap successfully`() {
        val encodedJsonMap = authorizationResponse.toJsonEncodedMap()

        assertEquals(
            mapOf(
                "presentation_submission" to "{\"id\":\"ps_id\",\"definition_id\":\"client_id\",\"descriptor_map\":[{\"id\":\"input_descriptor_1\",\"format\":\"ldp_vp\",\"path\":\"$\",\"path_nested\":{\"id\":\"input_descriptor_1\",\"format\":\"ldp_vp\",\"path\":\"$.verifiableCredential[0]\"}}]}",
                "vp_token" to "{\"@context\":[\"context\"],\"type\":[\"type\"],\"verifiableCredential\":[\"VC1\"],\"id\":\"id\",\"holder\":\"holder\",\"proof\":{\"type\":\"type\",\"created\":\"time\",\"challenge\":\"challenge\",\"domain\":\"domain\",\"jws\":\"eryy....ewr\",\"proofPurpose\":\"authentication\",\"verificationMethod\":\"did:example:holder#key-1\"}}",
                "state" to "state"
            ),
            encodedJsonMap
        )
    }

    @Test
    fun `should create encodedJsonMap with no nullable fields`() {
        val authorizationResponse = AuthorizationResponse(
            presentationSubmission = presentationSubmission,
            vpToken = vpToken,
            state = null
        )

        val encodedJsonMap = authorizationResponse.toJsonEncodedMap()

        assertEquals(
            mapOf(
                "presentation_submission" to "{\"id\":\"ps_id\",\"definition_id\":\"client_id\",\"descriptor_map\":[{\"id\":\"input_descriptor_1\",\"format\":\"ldp_vp\",\"path\":\"$\",\"path_nested\":{\"id\":\"input_descriptor_1\",\"format\":\"ldp_vp\",\"path\":\"$.verifiableCredential[0]\"}}]}",
                "vp_token" to "{\"@context\":[\"context\"],\"type\":[\"type\"],\"verifiableCredential\":[\"VC1\"],\"id\":\"id\",\"holder\":\"holder\",\"proof\":{\"type\":\"type\",\"created\":\"time\",\"challenge\":\"challenge\",\"domain\":\"domain\",\"jws\":\"eryy....ewr\",\"proofPurpose\":\"authentication\",\"verificationMethod\":\"did:example:holder#key-1\"}}"
            ),
            encodedJsonMap
        )
    }
}