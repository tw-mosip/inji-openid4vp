package io.mosip.openID4VP.authorizationResponse

import android.util.Log
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.verify
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.authorizationResponse.exception.AuthorizationResponseExceptions
import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.types.LdpVPTokenForSigning
import io.mosip.openID4VP.common.DateUtil
import io.mosip.openID4VP.common.FormatType
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.testData.authorizationRequest
import io.mosip.openID4VP.testData.clientMetadataMap
import io.mosip.openID4VP.testData.presentationDefinitionMap
import io.mosip.openID4VP.testData.setField
import io.mosip.openID4VP.testData.vpResponsesMetadata
import org.junit.Assert
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

class AuthorizationResponseHandlerTest {
    private val selectedCredentialsList = mapOf(
        "456" to mapOf(
            FormatType.LDP_VC to listOf(
                """{"format":"ldp_vc","verifiableCredential":{"credential":{"issuanceDate":"2024-08-02T16:04:35.304Z","credentialSubject":{"face":"data:image/jpeg;base64,/9j/goKCyuig","dateOfBirth":"2000/01/01","id":"did:jwk:eyJr80435=","UIN":"9012378996","email":"mockuser@gmail.com"},"id":"https://domain.net/credentials/12345-87435","proof":{"type":"RsaSignature2018","created":"2024-04-14T16:04:35Z","proofPurpose":"assertionMethod","verificationMethod":"https://domain.net/.well-known/public-key.json","jws":"eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ"},"type":["VerifiableCredential"],"@context":["https://www.w3.org/2018/credentials/v1","https://domain.net/.well-known/context.json",{"sec":"https://w3id.org/security#"}],"issuer":"https://domain.net/.well-known/issuer.json"}}}""",
                """{"verifiableCredential":{"credential":{"issuanceDate":"2024-08-12T18:03:35.304Z","credentialSubject":{"face":"data:image/jpeg;base64,/9j/goKCyuig","dateOfBirth":"2000/01/01","id":"did:jwk:eyJr80435=","UIN":"9012378996","email":"mockuser@gmail.com"},"id":"https://domain.net/credentials/12345-87435","proof":{"type":"RsaSignature2018","created":"2024-04-14T16:04:35Z","proofPurpose":"assertionMethod","verificationMethod":"https://domain.net/.well-known/public-key.json","jws":"eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ"},"type":["VerifiableCredential"],"@context":["https://www.w3.org/2018/credentials/v1","https://domain.net/.well-known/context.json",{"sec":"https://w3id.org/security#"}],"issuer":"https://domain.net/.well-known/issuer.json"}}}"""
            )
        ), "789" to mapOf(
            FormatType.LDP_VC to listOf(
                """{"format":"ldp_vc","verifiableCredential":{"credential":{"issuanceDate":"2024-08-18T13:02:35.304Z","credentialSubject":{"face":"data:image/jpeg;base64,/9j/goKCyuig","dateOfBirth":"2000/01/01","id":"did:jwk:eyJr80435=","UIN":"9012378996","email":"mockuser@gmail.com"},"id":"https://domain.net/credentials/12345-87435","proof":{"type":"RsaSignature2018","created":"2024-04-14T16:04:35Z","proofPurpose":"assertionMethod","verificationMethod":"https://domain.net/.well-known/public-key.json","jws":"eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ"},"type":["VerifiableCredential"],"@context":["https://www.w3.org/2018/credentials/v1","https://domain.net/.well-known/context.json",{"sec":"https://w3id.org/security#"}],"issuer":"https://domain.net/.well-known/issuer.json"}}}"""
            )
        )
    )
    private val ldpVpTokenForSigning: LdpVPTokenForSigning = LdpVPTokenForSigning(
        context = listOf("https://www.w3.org/2018/credentials/v1"),
        type = listOf("VerifiableCredential"),
        verifiableCredential = listOf("VC1", "VC2", "VC3"),
        id = "id",
        holder = "",
    )

    private val vpTokensForSigning = mapOf(FormatType.LDP_VC to ldpVpTokenForSigning)
    private lateinit var authorizationResponseHandler: AuthorizationResponseHandler

    @Before
    fun setUp() {
        authorizationResponseHandler = AuthorizationResponseHandler()
        setField(authorizationResponseHandler, "credentialsMap", selectedCredentialsList)
        setField(authorizationResponseHandler, "vpTokensForSigning", this.vpTokensForSigning)

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

        mockkObject(NetworkManagerClient)
    }


    @Test
    fun `should make network call to verifier responseUri with the vp_token, presentation_submission and state successfully`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com",
                HTTP_METHOD.POST,
                any(),
                any()
            )
        } returns mapOf("body" to "VP share success")
        val expectedBodyWithAuthResponseParams = mapOf(
            "vp_token" to "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"type\":[\"VerifiableCredential\"],\"verifiableCredential\":[\"VC1\",\"VC2\",\"VC3\"],\"id\":\"id\",\"holder\":\"\",\"proof\":{\"type\":\"RsaSignature2018\",\"created\":\"2024-02-13T10:00:00Z\",\"challenge\":\"bMHvX1HGhbh8zqlSWf/fuQ==\",\"domain\":\"https://123\",\"jws\":\"eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ\",\"proofPurpose\":\"authentication\",\"verificationMethod\":\"-----BEGIN RSA PUBLIC KEY-----\\n        MIICCgKCAgEA0IEd3E5CvLAbGvr/ysYT2TLE7WDrPBHGk8pwGqVvlrrFtZJ9wT8E\\n        lDNkSfHIgBijphkgSXpVMduwWKidiFFtbqQHgKdr4vdiMKzTy8g0aTpD8T5xPImM\\n        CC6CUVgp4EZZHkFK3S2guLZAanXLju3WBD4FuBQTl08vP5MlsiseIIanOnTulUDR\\n        baGIYhONq2kN9UnLIXcv8QPIgroP/n76Ir39EwRd20E4jsNfEriZFthBZKQLNbTz\\n        GrsVMtpUbHPUlvACrTzXm5RQ1THHDYUa46KmxZfTCKWM2EppaoJlUj1psf3LdlOU\\n        MBAarn+3QUxYOMLu9vTLvqsk606WNbeuiHarY6lBAec1E6RXMIcVLKBqMy6NjMCK\\n        Va3ZFvn6/G9JI0U+S8Nn3XpH5nLnyAwim7+l9ZnmqeKTTcnE8oxEuGdP7+VvpyHE\\n        AF8jilspP0PuBLMNV4eNthKPKPfMvBbFtzLcizqXmSLPx8cOtrEOu+cEU6ckavAS\\n        XwPgM27JUjeBwwnAhS8lrN3SiJLYCCi1wXjgqFgESNTBhHq+/H5Mb2wxliJQmfzd\\n        BQOI7kr7ICohW8y2ivCBKGR3dB9j7l77C0o/5pzkHElESdR2f3q+nXfHds2NmoRU\\n        IGZojdVF+LrGiwRBRUvZMlSKUdsoYVAxz/a5ISGIrWCOd9PgDO5RNNUCAwEAAQ==\\n        -----END RSA PUBLIC KEY-----\"}}",
            "presentation_submission" to "{\"id\":\"649d581c-f291-4969-9cd5-2c27385a348f\",\"definition_id\":\"649d581c-f891-4969-9cd5-2c27385a348f\",\"descriptor_map\":[{\"id\":\"456\",\"format\":\"ldp_vc\",\"path\":\"\$\",\"path_nested\":{\"id\":\"456\",\"format\":\"ldp_vc\",\"path\":\"\$.VerifiableCredential[0]\"}},{\"id\":\"456\",\"format\":\"ldp_vc\",\"path\":\"\$\",\"path_nested\":{\"id\":\"456\",\"format\":\"ldp_vc\",\"path\":\"\$.VerifiableCredential[1]\"}},{\"id\":\"789\",\"format\":\"ldp_vc\",\"path\":\"\$\",\"path_nested\":{\"id\":\"789\",\"format\":\"ldp_vc\",\"path\":\"\$.VerifiableCredential[2]\"}}]}",
            "state" to "fsnC8ixCs6mWyV+00k23Qg=="
        )
        val expectedHeaders = mapOf("Content-Type" to "application/x-www-form-urlencoded")

        authorizationResponseHandler.shareVP(
            authorizationRequest = authorizationRequest,
            vpResponsesMetadata = vpResponsesMetadata,
            responseUri = authorizationRequest.responseUri!!
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                url = authorizationRequest.responseUri!!,
                method = HTTP_METHOD.POST,
                bodyParams = expectedBodyWithAuthResponseParams,
                headers = expectedHeaders
            )
        }
    }

    @Test
    fun `should make network call to verifier responseUri with the vp_token, presentation_submission successfully`() {
        val authorizationRequestWithoutStateProperty = AuthorizationRequest(
            clientId = "https://mock-verifier.com",
            responseType = "vp_token",
            responseMode = "direct_post",
            presentationDefinition = deserializeAndValidate(
                presentationDefinitionMap,
                PresentationDefinitionSerializer
            ),
            nonce = "bMHvX1HGhbh8zqlSWf/fuQ==",
            state = null,
            responseUri = "https://mock-verifier.com",
            clientMetadata = deserializeAndValidate(clientMetadataMap, ClientMetadataSerializer),
            clientIdScheme = "redirect_uri",
            redirectUri = null
        )
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com",
                HTTP_METHOD.POST,
                any(),
                any()
            )
        } returns mapOf("body" to "VP share success")
        val expectedBodyWithAuthResponseParams = mapOf(
            "vp_token" to "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"type\":[\"VerifiableCredential\"],\"verifiableCredential\":[\"VC1\",\"VC2\",\"VC3\"],\"id\":\"id\",\"holder\":\"\",\"proof\":{\"type\":\"RsaSignature2018\",\"created\":\"2024-02-13T10:00:00Z\",\"challenge\":\"bMHvX1HGhbh8zqlSWf/fuQ==\",\"domain\":\"https://123\",\"jws\":\"eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ\",\"proofPurpose\":\"authentication\",\"verificationMethod\":\"-----BEGIN RSA PUBLIC KEY-----\\n        MIICCgKCAgEA0IEd3E5CvLAbGvr/ysYT2TLE7WDrPBHGk8pwGqVvlrrFtZJ9wT8E\\n        lDNkSfHIgBijphkgSXpVMduwWKidiFFtbqQHgKdr4vdiMKzTy8g0aTpD8T5xPImM\\n        CC6CUVgp4EZZHkFK3S2guLZAanXLju3WBD4FuBQTl08vP5MlsiseIIanOnTulUDR\\n        baGIYhONq2kN9UnLIXcv8QPIgroP/n76Ir39EwRd20E4jsNfEriZFthBZKQLNbTz\\n        GrsVMtpUbHPUlvACrTzXm5RQ1THHDYUa46KmxZfTCKWM2EppaoJlUj1psf3LdlOU\\n        MBAarn+3QUxYOMLu9vTLvqsk606WNbeuiHarY6lBAec1E6RXMIcVLKBqMy6NjMCK\\n        Va3ZFvn6/G9JI0U+S8Nn3XpH5nLnyAwim7+l9ZnmqeKTTcnE8oxEuGdP7+VvpyHE\\n        AF8jilspP0PuBLMNV4eNthKPKPfMvBbFtzLcizqXmSLPx8cOtrEOu+cEU6ckavAS\\n        XwPgM27JUjeBwwnAhS8lrN3SiJLYCCi1wXjgqFgESNTBhHq+/H5Mb2wxliJQmfzd\\n        BQOI7kr7ICohW8y2ivCBKGR3dB9j7l77C0o/5pzkHElESdR2f3q+nXfHds2NmoRU\\n        IGZojdVF+LrGiwRBRUvZMlSKUdsoYVAxz/a5ISGIrWCOd9PgDO5RNNUCAwEAAQ==\\n        -----END RSA PUBLIC KEY-----\"}}",
            "presentation_submission" to "{\"id\":\"649d581c-f291-4969-9cd5-2c27385a348f\",\"definition_id\":\"649d581c-f891-4969-9cd5-2c27385a348f\",\"descriptor_map\":[{\"id\":\"456\",\"format\":\"ldp_vc\",\"path\":\"\$\",\"path_nested\":{\"id\":\"456\",\"format\":\"ldp_vc\",\"path\":\"\$.VerifiableCredential[0]\"}},{\"id\":\"456\",\"format\":\"ldp_vc\",\"path\":\"\$\",\"path_nested\":{\"id\":\"456\",\"format\":\"ldp_vc\",\"path\":\"\$.VerifiableCredential[1]\"}},{\"id\":\"789\",\"format\":\"ldp_vc\",\"path\":\"\$\",\"path_nested\":{\"id\":\"789\",\"format\":\"ldp_vc\",\"path\":\"\$.VerifiableCredential[2]\"}}]}"
        )
        val expectedHeaders = mapOf("Content-Type" to "application/x-www-form-urlencoded")

        authorizationResponseHandler.shareVP(
            authorizationRequest = authorizationRequestWithoutStateProperty,
            vpResponsesMetadata = vpResponsesMetadata,
            responseUri = authorizationRequest.responseUri!!
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                url = authorizationRequest.responseUri!!,
                method = HTTP_METHOD.POST,
                bodyParams = expectedBodyWithAuthResponseParams,
                headers = expectedHeaders
            )
        }
    }

    @Test
    fun `should throw error during construction of data for signing when selected Credentials is empty`() {
        val actualException =
            assertThrows(AuthorizationResponseExceptions.EmptyCredentialsList::class.java) {
                authorizationResponseHandler.constructVPTokenForSigning(
                    credentialsMap = mapOf(),
                    holder = ""
                )
            }

        Assert.assertEquals(
            "Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request.",
            actualException.message
        )
    }

    @Test
    fun `should throw error when response type is not supported`() {
        val authorizationRequestWithNonVPTokenResponseType = AuthorizationRequest(
            clientId = "https://mock-verifier.com",
            responseType = "code",
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
            assertThrows(AuthorizationResponseExceptions.UnsupportedResponseType::class.java) {
                authorizationResponseHandler.shareVP(
                    authorizationRequest = authorizationRequestWithNonVPTokenResponseType,
                    vpResponsesMetadata = vpResponsesMetadata,
                    responseUri = authorizationRequest.responseUri!!
                )
            }

        Assert.assertEquals(
            "Provided response_type - code is not supported",
            actualException.message
        )
    }
}