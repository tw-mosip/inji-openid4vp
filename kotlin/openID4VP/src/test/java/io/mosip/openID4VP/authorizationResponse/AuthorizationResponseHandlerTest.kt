package io.mosip.openID4VP.authorizationResponse

import android.util.Log
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.authorizationResponse.exception.AuthorizationResponseExceptions
import io.mosip.openID4VP.authorizationResponse.models.AuthorizationResponse
import io.mosip.openID4VP.authorizationResponse.models.vpToken.types.LdpVPToken
import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.types.LdpVpSpecificSigningData
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.common.DateUtil
import io.mosip.openID4VP.common.FormatType
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.dto.VPResponseMetadata.types.LdpVPResponseMetadata
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.testData.clientMetadata
import io.mosip.openID4VP.testData.presentationDefinition
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue

class AuthorizationResponseHandlerTest {
    val authorizationRequest = AuthorizationRequest(
        clientId = "https://mock-verifier.com",
        responseType = "vp_token",
        responseMode = "direct_post",
        presentationDefinition = deserializeAndValidate(
            presentationDefinition,
            PresentationDefinitionSerializer
        ),
        nonce = "bMHvX1HGhbh8zqlSWf/fuQ==",
        state = "fsnC8ixCs6mWyV+00k23Qg==",
        responseUri = "https://mock-verifier.com",
        clientMetadata = deserializeAndValidate(clientMetadata, ClientMetadataSerializer),
        clientIdScheme = "redirect_uri",
        redirectUri = null
    )
    private val vpTokensForSigning = mapOf(
        FormatType.ldp_vc to LdpVpSpecificSigningData(
            verifiableCredential = listOf("VC1", "VC2"),
            id = "id-12",
            holder = "wallet-holder"
        )
    )
    private val credentialsMap: Map<String, Map<String, List<Any>>> =
        mapOf("idcardcredential" to mapOf("ldp_vc" to listOf("VC1", "VC2")))
    private val ldpVPResponseMetadata: LdpVPResponseMetadata = LdpVPResponseMetadata(
        "eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ",
        "RsaSignature2018",
        "--PUBLIC KEY--",
        "https://123",
    )
    private val vpResponsesMetadata = mapOf(FormatType.ldp_vc to ldpVPResponseMetadata)
    private val authorizationResponse = AuthorizationResponse(
        vpToken = VPTokenType.VPToken(
            LdpVPToken(
                verifiableCredential = listOf("VC1", "VC2"),
                id = "ldp_vp_id",
                holder = "wallet-holder",
                proof = Proof(
                    type = ldpVPResponseMetadata.signatureAlgorithm,
                    created = "2024-07-18T10:00:00Z",
                    challenge = "challenge",
                    domain = "domain",
                    jws = ldpVPResponseMetadata.jws,
                    verificationMethod = ldpVPResponseMetadata.publicKey
                )
            )
        ),
        presentationSubmission = PresentationSubmission(
            id = "presentation-submission-id",
            definitionId = "https://mock-verifier.com",
            descriptorMap = listOf(
                DescriptorMap(
                    id = "idcardcredential",
                    format = "ldp_vp",
                    path = "$",
                    pathNested = "$.verifiableCredential[0]"
                )
            )
        )
    )


    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.e(any(), any()) } answers {
            val tag = arg<String>(0)
            val msg = arg<String>(1)
            println("Error: logTag: $tag | Message: $msg")
            0
        }

        mockkObject(UUIDGenerator)
        every { UUIDGenerator.generateUUID() } returns "649d581c-f291-4969-9cd5-2c27385a348f"

        mockkObject(DateUtil)
        every { DateUtil.formattedCurrentDateTime() } returns "2024-02-13T10:00:00Z"
    }

    @Test
    fun `should return authorization response successfully when the selected credentials is provided`() {
        val expectedAuthorizationResponseEncodedItems = mapOf(
            "vp_token" to "{\"verifiableCredential\":[\"VC1\",\"VC2\"],\"id\":\"id-12\",\"holder\":\"wallet-holder\",\"proof\":{\"type\":\"RsaSignature2018\",\"created\":\"2024-02-13T10:00:00Z\",\"challenge\":\"bMHvX1HGhbh8zqlSWf/fuQ==\",\"domain\":\"https://123\",\"jws\":\"eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ\",\"verificationMethod\":\"--PUBLIC KEY--\"}}",
            "presentation_submission" to "{\"id\":\"649d581c-f291-4969-9cd5-2c27385a348f\",\"definition_id\":\"https://mock-verifier.com\",\"descriptor_map\":[{\"id\":\"idcardcredential\",\"format\":\"ldp_vc\",\"path\":\"\$\",\"path_nested\":\"\$.VerifiableCredential[0]\"}]}"
        )

        val authorizationResponse =
            AuthorizationResponseHandler().createAuthorizationResponse(
                authorizationRequest = authorizationRequest,
                signingDataForAuthorizationResponseCreation = vpResponsesMetadata,
                vpTokensForSigning = vpTokensForSigning,
                credentialsMap = credentialsMap
            )
        val encodedItems: Map<String, String> = authorizationResponse.encodedItems()

        assertTrue(expectedAuthorizationResponseEncodedItems.equals(encodedItems));
    }

    @Test
    fun `should throw error during construction of data for signing when selected Credentials is empty`() {
        val actualException =
            Assert.assertThrows(AuthorizationResponseExceptions.AccessDenied::class.java) {
                AuthorizationResponseHandler().constructDataForSigning(
                    credentialsMap = mapOf()
                )
            }

        Assert.assertEquals(
            "The Wallet did not have the requested Credentials to satisfy the Authorization Request.",
            actualException.message
        )
    }

    @Test
    fun `should throw exception when response_type in authorization request is not vp_token`() {
        val authorizationRequestWithUnsupportedResponseType = AuthorizationRequest(
            clientId = "redirect_uri:https://mock-verifier.com",
            responseType = "vp_token id_token",
            responseMode = "direct_post",
            presentationDefinition = deserializeAndValidate(
                presentationDefinition,
                PresentationDefinitionSerializer
            ),
            nonce = "bMHvX1HGhbh8zqlSWf/fuQ==",
            state = "fsnC8ixCs6mWyV+00k23Qg==",
            responseUri = "https://mock-verifier.com",
            clientMetadata = deserializeAndValidate(clientMetadata, ClientMetadataSerializer),
            clientIdScheme = "redirect_uri",
            redirectUri = null
        )

        val actualException =
            Assert.assertThrows(AuthorizationResponseExceptions.UnsupportedResponseType::class.java) {
                AuthorizationResponseHandler().createAuthorizationResponse(
                    authorizationRequest = authorizationRequestWithUnsupportedResponseType,
                    signingDataForAuthorizationResponseCreation = vpResponsesMetadata,
                    vpTokensForSigning = vpTokensForSigning,
                    credentialsMap = credentialsMap
                )
            }

        Assert.assertEquals(
            "Provided response_type vp_token id_token is not supported by the library",
            actualException.message
        )
    }

    @Test
    fun `should sent authorization response successfully to the verifier when response_mode is direct_post`() {
        mockkObject(NetworkManagerClient)
        every {
            NetworkManagerClient.sendHTTPRequest(
                url = "https://mock-verifier.com",
                method = HTTP_METHOD.POST,
                bodyParams = any(),
                headers = mapOf("Content-Type" to "application/x-www-form-urlencoded")
            )
        } returns "Verifiable Presentation is shared successfully"

        val responseToVerifier: String =
            AuthorizationResponseHandler().sendAuthorizationResponseToVerifier(
                authorizationResponse,
                authorizationRequest
            )

        assertEquals("Verifiable Presentation is shared successfully", responseToVerifier)
    }

    @Test
    fun `should throw exception when response_mode in authorization request is not direct_post`() {
        val authorizationRequestWithUnsupportedResponseMode = AuthorizationRequest(
            clientId = "redirect_uri:https://mock-verifier.com",
            responseType = "vp_token",
            responseMode = "fragment",
            presentationDefinition = deserializeAndValidate(
                presentationDefinition,
                PresentationDefinitionSerializer
            ),
            nonce = "bMHvX1HGhbh8zqlSWf/fuQ==",
            state = "fsnC8ixCs6mWyV+00k23Qg==",
            responseUri = "https://mock-verifier.com",
            clientMetadata = deserializeAndValidate(clientMetadata, ClientMetadataSerializer),
            clientIdScheme = "redirect_uri",
            redirectUri = null
        )

        val actualException =
            Assert.assertThrows(AuthorizationResponseExceptions.UnsupportedResponseMode::class.java) {
                AuthorizationResponseHandler().sendAuthorizationResponseToVerifier(
                    authorizationRequest = authorizationRequestWithUnsupportedResponseMode,
                    authorizationResponse = authorizationResponse,
                )
            }

        Assert.assertEquals(
            "Provided response_mode fragment is not supported by the library",
            actualException.message
        )
    }
}