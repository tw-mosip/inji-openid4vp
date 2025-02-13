package io.mosip.openID4VP.authorizationResponse

import android.util.Log
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.authorizationResponse.exception.AuthorizationResponseExceptions
import io.mosip.openID4VP.authorizationResponse.models.AuthorizationResponseModel
import io.mosip.openID4VP.authorizationResponse.models.vpToken.types.LdpVPToken
import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.types.LdpVpSpecificSigningData
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.common.FormatType
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.testData.clientMetadataMap
import io.mosip.openID4VP.testData.ldpVPResponseMetadata
import io.mosip.openID4VP.testData.presentationDefinitionMap
import org.junit.Assert
import org.junit.Before
import org.junit.Ignore
import org.junit.Test
import org.junit.jupiter.api.Assertions.assertEquals
import java.text.SimpleDateFormat
import java.util.Date

class AuthorizationResponseHandlerTest {
    val authorizationRequest = AuthorizationRequest(
        clientId = "https://mock-verifier.com",
        responseType = "vp_token",
        responseMode = "direct_post",
        presentationDefinition = deserializeAndValidate(
            presentationDefinitionMap,
            PresentationDefinitionSerializer
        ),
        nonce = "bMHvX1HGhbh8zqlSWf/fuQ==",
        state = "fsnC8ixCs6mWyV+00k23Qg==",
        responseUri = "https://mock-verifier.com",
        clientMetadata = deserializeAndValidate(clientMetadataMap, ClientMetadataSerializer),
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
    private val vpResponsesMetadata = mapOf(FormatType.ldp_vc to ldpVPResponseMetadata)
    val authorizationResponse = AuthorizationResponseModel(
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


    private val mockFormatter = mockk<SimpleDateFormat>()

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

        every { mockFormatter.format(any<Date>()) } returns "2024-02-13T10:00:00Z"
    }

    @Test
    @Ignore
    fun `should return authorization response successfully when the selected credentials is provided`() {
        val authorizationResponse =
            AuthorizationResponseHandler().createAuthorizationResponse(
                authorizationRequest = authorizationRequest,
                signingDataForAuthorizationResponseCreation = vpResponsesMetadata,
                vpTokensForSigning = vpTokensForSigning,
                credentialsMap = credentialsMap
            )

        //TODO: Failing because of time being populated dynamically, extract time as a separate object to ease mocking
        assertEquals(
            "{vp_token={\"type\":\"VPToken\",\"value\":{\"verifiableCredential\":[\"VC1\",\"VC2\"],\"id\":\"id-12\",\"holder\":\"wallet-holder\",\"proof\":{\"type\":\"RsaSignature2018\",\"created\":\"2025-02-13T22:24:15Z\",\"challenge\":\"bMHvX1HGhbh8zqlSWf/fuQ==\",\"domain\":\"https://123\",\"jws\":\"eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ\",\"verificationMethod\":\"-----BEGIN RSA PUBLIC KEY-----\\n        MIICCgKCAgEA0IEd3E5CvLAbGvr/ysYT2TLE7WDrPBHGk8pwGqVvlrrFtZJ9wT8E\\n        lDNkSfHIgBijphkgSXpVMduwWKidiFFtbqQHgKdr4vdiMKzTy8g0aTpD8T5xPImM\\n        CC6CUVgp4EZZHkFK3S2guLZAanXLju3WBD4FuBQTl08vP5MlsiseIIanOnTulUDR\\n        baGIYhONq2kN9UnLIXcv8QPIgroP/n76Ir39EwRd20E4jsNfEriZFthBZKQLNbTz\\n        GrsVMtpUbHPUlvACrTzXm5RQ1THHDYUa46KmxZfTCKWM2EppaoJlUj1psf3LdlOU\\n        MBAarn+3QUxYOMLu9vTLvqsk606WNbeuiHarY6lBAec1E6RXMIcVLKBqMy6NjMCK\\n        Va3ZFvn6/G9JI0U+S8Nn3XpH5nLnyAwim7+l9ZnmqeKTTcnE8oxEuGdP7+VvpyHE\\n        AF8jilspP0PuBLMNV4eNthKPKPfMvBbFtzLcizqXmSLPx8cOtrEOu+cEU6ckavAS\\n        XwPgM27JUjeBwwnAhS8lrN3SiJLYCCi1wXjgqFgESNTBhHq+/H5Mb2wxliJQmfzd\\n        BQOI7kr7ICohW8y2ivCBKGR3dB9j7l77C0o/5pzkHElESdR2f3q+nXfHds2NmoRU\\n        IGZojdVF+LrGiwRBRUvZMlSKUdsoYVAxz/a5ISGIrWCOd9PgDO5RNNUCAwEAAQ==\\n        -----END RSA PUBLIC KEY-----\"}}}, presentation_submission={\"id\":\"649d581c-f291-4969-9cd5-2c27385a348f\",\"definition_id\":\"https://mock-verifier.com\",\"descriptor_map\":[{\"id\":\"idcardcredential\",\"format\":\"ldp_vc\",\"path\":\"\$\",\"path_name\":\"\$.VerifiableCredential[0]\"}]}}",
            authorizationResponse.encodedItems()
        )
    }

    @Test
    fun `should throw exception when response_type in authorization request is not vp_token`() {
        val authorizationRequestWithUnsupportedResponseType = AuthorizationRequest(
            clientId = "redirect_uri:https://mock-verifier.com",
            responseType = "vp_token id_token",
            responseMode = "direct_post",
            presentationDefinition = deserializeAndValidate(
                presentationDefinitionMap,
                PresentationDefinitionSerializer
            ),
            nonce = "bMHvX1HGhbh8zqlSWf/fuQ==",
            state = "fsnC8ixCs6mWyV+00k23Qg==",
            responseUri = "https://mock-verifier.com",
            clientMetadata = deserializeAndValidate(clientMetadataMap, ClientMetadataSerializer),
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
        } returns mapOf("body" to "Verifiable Presentation is shared successfully")

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
                presentationDefinitionMap,
                PresentationDefinitionSerializer
            ),
            nonce = "bMHvX1HGhbh8zqlSWf/fuQ==",
            state = "fsnC8ixCs6mWyV+00k23Qg==",
            responseUri = "https://mock-verifier.com",
            clientMetadata = deserializeAndValidate(clientMetadataMap, ClientMetadataSerializer),
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