package io.mosip.openID4VP.authorizationResponse

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.verify
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPTokenBuilder
import io.mosip.openID4VP.common.DateUtil
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.exceptions.Exceptions
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.jwt.jwe.JWEHandler
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.testData.authorizationRequest
import io.mosip.openID4VP.testData.authorizationRequestForResponseModeJWT
import io.mosip.openID4VP.testData.clientMetadataMap
import io.mosip.openID4VP.testData.presentationDefinitionMap
import io.mosip.openID4VP.testData.setField
import io.mosip.openID4VP.testData.ldpAuthenticationContainerMap
import io.mosip.openID4VP.testData.ldpCredential1
import io.mosip.openID4VP.testData.ldpCredential2
import io.mosip.openID4VP.testData.ldpVPToken
import io.mosip.openID4VP.testData.mdocAuthenticationContainerMap
import io.mosip.openID4VP.testData.mdocCredential
import io.mosip.openID4VP.testData.mdocVPToken
import io.mosip.openID4VP.testData.unsignedLdpVPToken
import io.mosip.openID4VP.testData.unsignedMdocVPToken
import io.mosip.openID4VP.testData.unsignedVPTokens
import org.junit.After
import org.junit.Assert
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull

class AuthorizationResponseHandlerTest {
    private val ldpVcList1 = listOf(
        ldpCredential1,
        ldpCredential2
    )
    private val ldpVcList2 = listOf(
        ldpCredential2
    )
    private val mdocVcList = listOf(mdocCredential)
    private val selectedLdpVcCredentialsList = mapOf(
        "456" to mapOf(
            FormatType.LDP_VC to ldpVcList1
        ), "789" to mapOf(
            FormatType.LDP_VC to ldpVcList2
        )
    )
    private val selectedMdocCredentialsList = mapOf(
        "123" to mapOf(
            FormatType.MSO_MDOC to mdocVcList
        )
    )

    private lateinit var authorizationResponseHandler: AuthorizationResponseHandler

    @Before
    fun setUp() {
        authorizationResponseHandler = AuthorizationResponseHandler()
        setField(authorizationResponseHandler, "credentialsMap", selectedLdpVcCredentialsList)

         val unsignedLdpVPTokenForReflection =  UnsignedLdpVPToken(
            context = listOf("https://www.w3.org/2018/credentials/v1"),
            type = listOf("VerifiablePresentation"),
            verifiableCredential = listOf("credential1", "credential2", "credential3"),
            id = "649d581c-f291-4969-9cd5-2c27385a348f",
            holder = "",
        )

        val unsignedVPTokens =
            mapOf(FormatType.LDP_VC to unsignedLdpVPTokenForReflection)

        setField(authorizationResponseHandler, "unsignedVPTokens", unsignedVPTokens)

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

    @After
    fun tearDown() {
        clearAllMocks()
    }

//    construction of vpTokens for signing

    @Test
    fun `should successfully construct unsigned VP tokens for both LDP_VC and MSO_MDOC formats`() {

        mockkConstructor(UnsignedLdpVPTokenBuilder::class)
        every { anyConstructed<UnsignedLdpVPTokenBuilder>().build() } returns unsignedLdpVPToken

        mockkConstructor(UnsignedMdocVPTokenBuilder::class)
        every { anyConstructed<UnsignedMdocVPTokenBuilder>().build() } returns unsignedMdocVPToken

        val expectedUnsignedVPToken = mapOf(
            FormatType.LDP_VC to unsignedLdpVPToken,
            FormatType.MSO_MDOC to unsignedMdocVPToken
        )

        val unsignedVPToken = authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap =   selectedMdocCredentialsList+selectedLdpVcCredentialsList,
            authorizationRequest = authorizationRequest,
            responseUri = "https://mock-verifier.com",
        )

        assertNotNull(unsignedVPToken)
        assertEquals(2, unsignedVPToken.size)
        assertEquals(expectedUnsignedVPToken[FormatType.LDP_VC], unsignedVPToken[FormatType.LDP_VC])
        assertEquals(expectedUnsignedVPToken[FormatType.MSO_MDOC], unsignedVPToken[FormatType.MSO_MDOC])
    }


    @Test
    fun `should throw error during construction of data for signing when selected Credentials is empty`() {
        val actualException =
            assertThrows(Exceptions.InvalidData::class.java) {
                authorizationResponseHandler.constructUnsignedVPToken(
                    credentialsMap = mapOf(),
                    authorizationRequest = authorizationRequest,
                    responseUri = "https://mock-verifier.com",
                )
            }

        Assert.assertEquals(
            "Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request.",
            actualException.message
        )
    }

    // Sharing of Verifiable Presentation

    @Test
    fun `should make network call to verifier responseUri with the vp_token, presentation_submission and state successfully`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com",
                HttpMethod.POST,
                any(),
                any()
            )
        } returns mapOf("body" to "VP share success")
        val expectedBodyWithAuthResponseParams = mapOf(
            "vp_token" to "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"type\":[\"VerifiablePresentation\"],\"verifiableCredential\":[\"credential1\",\"credential2\",\"credential3\"],\"id\":\"649d581c-f291-4969-9cd5-2c27385a348f\",\"holder\":\"\",\"proof\":{\"type\":\"RsaSignature2018\",\"created\":\"2024-02-13T10:00:00Z\",\"challenge\":\"bMHvX1HGhbh8zqlSWf/fuQ==\",\"domain\":\"https://123\",\"jws\":\"eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ\",\"proofPurpose\":\"authentication\",\"verificationMethod\":\"-----BEGIN RSA PUBLIC KEY-----\\n        MIICCgKCAgEA0IEd3E5CvLAbGvr/ysYT2TLE7WDrPBHGk8pwGqVvlrrFtZJ9wT8E\\n        lDNkSfHIgBijphkgSXpVMduwWKidiFFtbqQHgKdr4vdiMKzTy8g0aTpD8T5xPImM\\n        CC6CUVgp4EZZHkFK3S2guLZAanXLju3WBD4FuBQTl08vP5MlsiseIIanOnTulUDR\\n        baGIYhONq2kN9UnLIXcv8QPIgroP/n76Ir39EwRd20E4jsNfEriZFthBZKQLNbTz\\n        GrsVMtpUbHPUlvACrTzXm5RQ1THHDYUa46KmxZfTCKWM2EppaoJlUj1psf3LdlOU\\n        MBAarn+3QUxYOMLu9vTLvqsk606WNbeuiHarY6lBAec1E6RXMIcVLKBqMy6NjMCK\\n        Va3ZFvn6/G9JI0U+S8Nn3XpH5nLnyAwim7+l9ZnmqeKTTcnE8oxEuGdP7+VvpyHE\\n        AF8jilspP0PuBLMNV4eNthKPKPfMvBbFtzLcizqXmSLPx8cOtrEOu+cEU6ckavAS\\n        XwPgM27JUjeBwwnAhS8lrN3SiJLYCCi1wXjgqFgESNTBhHq+/H5Mb2wxliJQmfzd\\n        BQOI7kr7ICohW8y2ivCBKGR3dB9j7l77C0o/5pzkHElESdR2f3q+nXfHds2NmoRU\\n        IGZojdVF+LrGiwRBRUvZMlSKUdsoYVAxz/a5ISGIrWCOd9PgDO5RNNUCAwEAAQ==\\n        -----END RSA PUBLIC KEY-----\"}}",
            "presentation_submission" to "{\"id\":\"649d581c-f291-4969-9cd5-2c27385a348f\",\"definition_id\":\"649d581c-f891-4969-9cd5-2c27385a348f\",\"descriptor_map\":[{\"id\":\"456\",\"format\":\"ldp_vp\",\"path\":\"\$\",\"path_nested\":{\"id\":\"456\",\"format\":\"ldp_vc\",\"path\":\"\$.VerifiableCredential[0]\"}},{\"id\":\"456\",\"format\":\"ldp_vp\",\"path\":\"\$\",\"path_nested\":{\"id\":\"456\",\"format\":\"ldp_vc\",\"path\":\"\$.VerifiableCredential[1]\"}},{\"id\":\"789\",\"format\":\"ldp_vp\",\"path\":\"\$\",\"path_nested\":{\"id\":\"789\",\"format\":\"ldp_vc\",\"path\":\"\$.VerifiableCredential[2]\"}}]}",
            "state" to "fsnC8ixCs6mWyV+00k23Qg=="
        )
        val expectedHeaders = mapOf("Content-Type" to "application/x-www-form-urlencoded")

        authorizationResponseHandler.shareVP(
            authorizationRequest = authorizationRequest,
            authenticationContainerMap = ldpAuthenticationContainerMap,
            responseUri = authorizationRequest.responseUri!!
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                url = authorizationRequest.responseUri!!,
                method = HttpMethod.POST,
                bodyParams = expectedBodyWithAuthResponseParams,
                headers = expectedHeaders
            )
        }
    }

    @Test
    fun `should make network call to verifier responseUri with encrypted body successfully when both mdoc vc is being shared`() {
        mockkConstructor(LdpVPTokenBuilder::class)
        every { anyConstructed<LdpVPTokenBuilder>().build() } returns ldpVPToken

        mockkConstructor(MdocVPTokenBuilder::class)
        every { anyConstructed<MdocVPTokenBuilder>().build() } returns mdocVPToken

        setField(authorizationResponseHandler, "credentialsMap", selectedLdpVcCredentialsList + selectedMdocCredentialsList)
        setField(authorizationResponseHandler, "unsignedVPTokens", unsignedVPTokens)



        every {
            NetworkManagerClient.sendHTTPRequest(
                authorizationRequestForResponseModeJWT.responseUri!!,
                HttpMethod.POST,
                any(),
                any()
            )
        } returns mapOf("body" to "VP share success")

        mockkConstructor(JWEHandler::class)
        every { anyConstructed<JWEHandler>().generateEncryptedResponse(any()) } returns "eytyiewr.....jewjr"
        val expectedBodyWithAuthResponseParams = mapOf(
            "response" to "eytyiewr.....jewjr"
        )
        val expectedHeaders = mapOf("Content-Type" to "application/x-www-form-urlencoded")

        authorizationResponseHandler.shareVP(
            authorizationRequest = authorizationRequestForResponseModeJWT,
            authenticationContainerMap = ldpAuthenticationContainerMap + mdocAuthenticationContainerMap,
            responseUri = authorizationRequestForResponseModeJWT.responseUri!!
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                url = authorizationRequestForResponseModeJWT.responseUri!!,
                method = HttpMethod.POST,
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
            responseUri = "https://mock-verifier.com",
            redirectUri = null,
            nonce = "bMHvX1HGhbh8zqlSWf/fuQ==",
            state = null,
            clientMetadata = deserializeAndValidate(clientMetadataMap, ClientMetadataSerializer)
        )
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com",
                HttpMethod.POST,
                any(),
                any()
            )
        } returns mapOf("body" to "VP share success")
        val expectedBodyWithAuthResponseParams = mapOf(
            "vp_token" to "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"type\":[\"VerifiablePresentation\"],\"verifiableCredential\":[\"credential1\",\"credential2\",\"credential3\"],\"id\":\"649d581c-f291-4969-9cd5-2c27385a348f\",\"holder\":\"\",\"proof\":{\"type\":\"RsaSignature2018\",\"created\":\"2024-02-13T10:00:00Z\",\"challenge\":\"bMHvX1HGhbh8zqlSWf/fuQ==\",\"domain\":\"https://123\",\"jws\":\"eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ\",\"proofPurpose\":\"authentication\",\"verificationMethod\":\"-----BEGIN RSA PUBLIC KEY-----\\n        MIICCgKCAgEA0IEd3E5CvLAbGvr/ysYT2TLE7WDrPBHGk8pwGqVvlrrFtZJ9wT8E\\n        lDNkSfHIgBijphkgSXpVMduwWKidiFFtbqQHgKdr4vdiMKzTy8g0aTpD8T5xPImM\\n        CC6CUVgp4EZZHkFK3S2guLZAanXLju3WBD4FuBQTl08vP5MlsiseIIanOnTulUDR\\n        baGIYhONq2kN9UnLIXcv8QPIgroP/n76Ir39EwRd20E4jsNfEriZFthBZKQLNbTz\\n        GrsVMtpUbHPUlvACrTzXm5RQ1THHDYUa46KmxZfTCKWM2EppaoJlUj1psf3LdlOU\\n        MBAarn+3QUxYOMLu9vTLvqsk606WNbeuiHarY6lBAec1E6RXMIcVLKBqMy6NjMCK\\n        Va3ZFvn6/G9JI0U+S8Nn3XpH5nLnyAwim7+l9ZnmqeKTTcnE8oxEuGdP7+VvpyHE\\n        AF8jilspP0PuBLMNV4eNthKPKPfMvBbFtzLcizqXmSLPx8cOtrEOu+cEU6ckavAS\\n        XwPgM27JUjeBwwnAhS8lrN3SiJLYCCi1wXjgqFgESNTBhHq+/H5Mb2wxliJQmfzd\\n        BQOI7kr7ICohW8y2ivCBKGR3dB9j7l77C0o/5pzkHElESdR2f3q+nXfHds2NmoRU\\n        IGZojdVF+LrGiwRBRUvZMlSKUdsoYVAxz/a5ISGIrWCOd9PgDO5RNNUCAwEAAQ==\\n        -----END RSA PUBLIC KEY-----\"}}",
            "presentation_submission" to "{\"id\":\"649d581c-f291-4969-9cd5-2c27385a348f\",\"definition_id\":\"649d581c-f891-4969-9cd5-2c27385a348f\",\"descriptor_map\":[{\"id\":\"456\",\"format\":\"ldp_vp\",\"path\":\"\$\",\"path_nested\":{\"id\":\"456\",\"format\":\"ldp_vc\",\"path\":\"\$.VerifiableCredential[0]\"}},{\"id\":\"456\",\"format\":\"ldp_vp\",\"path\":\"\$\",\"path_nested\":{\"id\":\"456\",\"format\":\"ldp_vc\",\"path\":\"\$.VerifiableCredential[1]\"}},{\"id\":\"789\",\"format\":\"ldp_vp\",\"path\":\"\$\",\"path_nested\":{\"id\":\"789\",\"format\":\"ldp_vc\",\"path\":\"\$.VerifiableCredential[2]\"}}]}"
        )
        val expectedHeaders = mapOf("Content-Type" to "application/x-www-form-urlencoded")

        authorizationResponseHandler.shareVP(
            authorizationRequest = authorizationRequestWithoutStateProperty,
            authenticationContainerMap = ldpAuthenticationContainerMap,
            responseUri = authorizationRequest.responseUri!!
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                url = authorizationRequest.responseUri!!,
                method = HttpMethod.POST,
                bodyParams = expectedBodyWithAuthResponseParams,
                headers = expectedHeaders
            )
        }
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
            responseUri = "https://mock-verifier.com",
            redirectUri = null,
            nonce = "bMHvX1HGhbh8zqlSWf/fuQ==",
            state = "fsnC8ixCs6mWyV+00k23Qg==",
            clientMetadata = deserializeAndValidate(clientMetadataMap, ClientMetadataSerializer)
        )

        val actualException =
            assertThrows(Exceptions.InvalidData::class.java) {
                authorizationResponseHandler.shareVP(
                    authorizationRequest = authorizationRequestWithNonVPTokenResponseType,
                    authenticationContainerMap = ldpAuthenticationContainerMap,
                    responseUri = authorizationRequest.responseUri!!
                )
            }

        Assert.assertEquals(
            "Provided response_type - code is not supported",
            actualException.message
        )
    }

    @Test
    fun `should throw error when a credential format entry is not available in unsignedVPTokens but available in authenticationContainerMap`() {
        setField(
            authorizationResponseHandler,
            "unsignedVPTokens",
            emptyMap<FormatType, UnsignedVPToken>()
        )
        val actualException =
            assertThrows(Exceptions.InvalidData::class.java) {
                authorizationResponseHandler.shareVP(
                    authorizationRequest = authorizationRequest,
                    authenticationContainerMap = ldpAuthenticationContainerMap,
                    responseUri = authorizationRequest.responseUri!!
                )
            }

        Assert.assertEquals(
            "unable to find the related credential format - LDP_VC in the unsignedVPTokens map",
            actualException.message
        )
    }


}