package io.mosip.openID4VP.authorizationResponse

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mosip.openID4VP.OpenId4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.dto.VPResponseMetadata
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

class AuthorizationResponseTest {
    private lateinit var openId4VP: OpenId4VP
    private val selectedCredentialsList = mapOf(
        "456" to listOf(
            "{\"credential\":{\"issuanceDate\":\"2024-08-02T16:04:35.304Z\",\"credentialSubject\":{\"face\":\"data:image/jpeg;base64,/9j/goKCyuig\",\"dateOfBirth\":\"2000/01/01\",\"id\":\"did:jwk:eyJr80435=\",\"UIN\":\"9012378996\",\"email\":\"mockuser@gmail.com\"},\"id\":\"https://domain.net/credentials/12345-87435\",\"proof\":{\"type\":\"RsaSignature2018\",\"created\":\"2024-04-14T16:04:35Z\",\"proofPurpose\":\"assertionMethod\",\"verificationMethod\":\"https://domain.net/.well-known/public-key.json\",\"jws\":\"eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ\"},\"type\":[\"VerifiableCredential\"],\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://domain.net/.well-known/context.json\",{\"sec\":\"https://w3id.org/security#\"}],\"issuer\":\"https://domain.net/.well-known/issuer.json\"}}",
            "{\"credential\":{\"issuanceDate\":\"2024-08-12T18:03:35.304Z\",\"credentialSubject\":{\"face\":\"data:image/jpeg;base64,/9j/goKCyuig\",\"dateOfBirth\":\"2000/01/01\",\"id\":\"did:jwk:eyJr80435=\",\"UIN\":\"9012378996\",\"email\":\"mockuser@gmail.com\"},\"id\":\"https://domain.net/credentials/12345-87435\",\"proof\":{\"type\":\"RsaSignature2018\",\"created\":\"2024-04-14T16:04:35Z\",\"proofPurpose\":\"assertionMethod\",\"verificationMethod\":\"https://domain.net/.well-known/public-key.json\",\"jws\":\"eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ\"},\"type\":[\"VerifiableCredential\"],\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://domain.net/.well-known/context.json\",{\"sec\":\"https://w3id.org/security#\"}],\"issuer\":\"https://domain.net/.well-known/issuer.json\"}}"
        ), "789" to listOf(
            "{\"credential\":{\"issuanceDate\":\"2024-08-18T13:02:35.304Z\",\"credentialSubject\":{\"face\":\"data:image/jpeg;base64,/9j/goKCyuig\",\"dateOfBirth\":\"2000/01/01\",\"id\":\"did:jwk:eyJr80435=\",\"UIN\":\"9012378996\",\"email\":\"mockuser@gmail.com\"},\"id\":\"https://domain.net/credentials/12345-87435\",\"proof\":{\"type\":\"RsaSignature2018\",\"created\":\"2024-04-14T16:04:35Z\",\"proofPurpose\":\"assertionMethod\",\"verificationMethod\":\"https://domain.net/.well-known/public-key.json\",\"jws\":\"eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ\"},\"type\":[\"VerifiableCredential\"],\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://domain.net/.well-known/context.json\",{\"sec\":\"https://w3id.org/security#\"}],\"issuer\":\"https://domain.net/.well-known/issuer.json\"}}"
        )
    )
    private val publicKey = """-----BEGIN RSA PUBLIC KEY-----
        MIICCgKCAgEA0IEd3E5CvLAbGvr/ysYT2TLE7WDrPBHGk8pwGqVvlrrFtZJ9wT8E
        lDNkSfHIgBijphkgSXpVMduwWKidiFFtbqQHgKdr4vdiMKzTy8g0aTpD8T5xPImM
        CC6CUVgp4EZZHkFK3S2guLZAanXLju3WBD4FuBQTl08vP5MlsiseIIanOnTulUDR
        baGIYhONq2kN9UnLIXcv8QPIgroP/n76Ir39EwRd20E4jsNfEriZFthBZKQLNbTz
        GrsVMtpUbHPUlvACrTzXm5RQ1THHDYUa46KmxZfTCKWM2EppaoJlUj1psf3LdlOU
        MBAarn+3QUxYOMLu9vTLvqsk606WNbeuiHarY6lBAec1E6RXMIcVLKBqMy6NjMCK
        Va3ZFvn6/G9JI0U+S8Nn3XpH5nLnyAwim7+l9ZnmqeKTTcnE8oxEuGdP7+VvpyHE
        AF8jilspP0PuBLMNV4eNthKPKPfMvBbFtzLcizqXmSLPx8cOtrEOu+cEU6ckavAS
        XwPgM27JUjeBwwnAhS8lrN3SiJLYCCi1wXjgqFgESNTBhHq+/H5Mb2wxliJQmfzd
        BQOI7kr7ICohW8y2ivCBKGR3dB9j7l77C0o/5pzkHElESdR2f3q+nXfHds2NmoRU
        IGZojdVF+LrGiwRBRUvZMlSKUdsoYVAxz/a5ISGIrWCOd9PgDO5RNNUCAwEAAQ==
        -----END RSA PUBLIC KEY-----"""
    private lateinit var presentationDefinition: String
    private lateinit var trustedVerifiers: List<Verifier>
    private lateinit var mockWebServer: MockWebServer
    private lateinit var expectedValue: String
    private lateinit var vpResponseMetadata: VPResponseMetadata

    @Before
    fun setUp() {
        openId4VP = OpenId4VP("123")
        presentationDefinition =
            "{\"id\":\"649d581c-f891-4969-9cd5-2c27385a348f\",\"input_descriptors\":[{\"id\":\"idcardcredential\",\"constraints\":{\"fields\":[{\"path\":[\"$.type\"]}]}}]}"
        trustedVerifiers = listOf(
            Verifier(
                "https://injiverify.dev2.mosip.net", listOf(
                    "https://injiverify.qa-inji.mosip.net/redirect",
                    "https://injiverify.dev2.mosip.net/redirect"
                )
            ), Verifier(
                "https://injiverify.dev1.mosip.net", listOf(
                    "https://injiverify.qa-inji.mosip.net/redirect",
                    "https://injiverify.dev1.mosip.net/redirect"
                )
            )
        )
        mockWebServer = MockWebServer()
        mockWebServer.start()
        openId4VP.presentationDefinitionId = "6498781c-f291-4969-9cd5-2c273858f38f"
        openId4VP.authorizationRequest = AuthorizationRequest(
            clientId = "https://injiverify.dev2.mosip.net",
            responseType = "vp_token",
            responseMode = "direct_post",
            presentationDefinition = presentationDefinition,
            nonce = "bMHvX1HGhbh8zqlSWf/fuQ==",
            state = "fsnC8ixCs6mWyV+00k23Qg==",
            scope = null,
            responseUri = mockWebServer.url("/https://injiverify.dev2.mosip.net/redirect")
                .toString()
        )
        openId4VP.constructVPToken(selectedCredentialsList)
        mockkStatic(Log::class)
        every { Log.e(any(), any()) } answers {
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
    fun `should construct VPToken in JsonString format using received selected verifiable credentials`() {
        expectedValue =
            "{\"verifiableCredential\":[\"{\\\"credential\\\":{\\\"issuanceDate\\\":\\\"2024-08-02T16:04:35.304Z\\\",\\\"credentialSubject\\\":{\\\"face\\\":\\\"data:image/jpeg;base64,/9j/goKCyuig\\\",\\\"dateOfBirth\\\":\\\"2000/01/01\\\",\\\"id\\\":\\\"did:jwk:eyJr80435=\\\",\\\"UIN\\\":\\\"9012378996\\\",\\\"email\\\":\\\"mockuser@gmail.com\\\"},\\\"id\\\":\\\"https://domain.net/credentials/12345-87435\\\",\\\"proof\\\":{\\\"type\\\":\\\"RsaSignature2018\\\",\\\"created\\\":\\\"2024-04-14T16:04:35Z\\\",\\\"proofPurpose\\\":\\\"assertionMethod\\\",\\\"verificationMethod\\\":\\\"https://domain.net/.well-known/public-key.json\\\",\\\"jws\\\":\\\"eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ\\\"},\\\"type\\\":[\\\"VerifiableCredential\\\"],\\\"@context\\\":[\\\"https://www.w3.org/2018/credentials/v1\\\",\\\"https://domain.net/.well-known/context.json\\\",{\\\"sec\\\":\\\"https://w3id.org/security#\\\"}],\\\"issuer\\\":\\\"https://domain.net/.well-known/issuer.json\\\"}}\",\"{\\\"credential\\\":{\\\"issuanceDate\\\":\\\"2024-08-12T18:03:35.304Z\\\",\\\"credentialSubject\\\":{\\\"face\\\":\\\"data:image/jpeg;base64,/9j/goKCyuig\\\",\\\"dateOfBirth\\\":\\\"2000/01/01\\\",\\\"id\\\":\\\"did:jwk:eyJr80435=\\\",\\\"UIN\\\":\\\"9012378996\\\",\\\"email\\\":\\\"mockuser@gmail.com\\\"},\\\"id\\\":\\\"https://domain.net/credentials/12345-87435\\\",\\\"proof\\\":{\\\"type\\\":\\\"RsaSignature2018\\\",\\\"created\\\":\\\"2024-04-14T16:04:35Z\\\",\\\"proofPurpose\\\":\\\"assertionMethod\\\",\\\"verificationMethod\\\":\\\"https://domain.net/.well-known/public-key.json\\\",\\\"jws\\\":\\\"eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ\\\"},\\\"type\\\":[\\\"VerifiableCredential\\\"],\\\"@context\\\":[\\\"https://www.w3.org/2018/credentials/v1\\\",\\\"https://domain.net/.well-known/context.json\\\",{\\\"sec\\\":\\\"https://w3id.org/security#\\\"}],\\\"issuer\\\":\\\"https://domain.net/.well-known/issuer.json\\\"}}\",\"{\\\"credential\\\":{\\\"issuanceDate\\\":\\\"2024-08-18T13:02:35.304Z\\\",\\\"credentialSubject\\\":{\\\"face\\\":\\\"data:image/jpeg;base64,/9j/goKCyuig\\\",\\\"dateOfBirth\\\":\\\"2000/01/01\\\",\\\"id\\\":\\\"did:jwk:eyJr80435=\\\",\\\"UIN\\\":\\\"9012378996\\\",\\\"email\\\":\\\"mockuser@gmail.com\\\"},\\\"id\\\":\\\"https://domain.net/credentials/12345-87435\\\",\\\"proof\\\":{\\\"type\\\":\\\"RsaSignature2018\\\",\\\"created\\\":\\\"2024-04-14T16:04:35Z\\\",\\\"proofPurpose\\\":\\\"assertionMethod\\\",\\\"verificationMethod\\\":\\\"https://domain.net/.well-known/public-key.json\\\",\\\"jws\\\":\\\"eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ\\\"},\\\"type\\\":[\\\"VerifiableCredential\\\"],\\\"@context\\\":[\\\"https://www.w3.org/2018/credentials/v1\\\",\\\"https://domain.net/.well-known/context.json\\\",{\\\"sec\\\":\\\"https://w3id.org/security#\\\"}],\\\"issuer\\\":\\\"https://domain.net/.well-known/issuer.json\\\"}}\"],\"id\":\"649d581c-f291-4969-9cd5-2c27385a348f\",\"holder\":\"\"}"
        mockkObject(UUIDGenerator)
        every { UUIDGenerator.generateUUID() } returns "649d581c-f291-4969-9cd5-2c27385a348f"

        val actualValue = openId4VP.constructVPToken(selectedCredentialsList)

        assertEquals(expectedValue, actualValue)
    }

    @Test
    fun `should throw invalid input exception if any input param of VPResponseMetadata class is empty`() {
        vpResponseMetadata = VPResponseMetadata(
            "eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ", "RsaSignature2018", publicKey, "", 3000
        )
        expectedValue = "Invalid Input: domain value cannot be empty or null"

        val invalidInputException =
            assertThrows(AuthorizationRequestExceptions.InvalidInput::class.java) {
                openId4VP.shareVerifiablePresentation(vpResponseMetadata)
            }

        assertEquals(expectedValue, invalidInputException.message)
    }

    @Test
    fun `should throw exception if Authorization Response request call returns the response with http status other than 200`() {
        val mockResponse: MockResponse = MockResponse().setResponseCode(500)
        mockWebServer.enqueue(mockResponse)
        vpResponseMetadata = VPResponseMetadata(
            "eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ",
            "RsaSignature2018",
            publicKey,
            "https://123",
            1000
        )
        expectedValue = "VP sharing failed due to this error - Server Error"

        val networkRequestFailedException =
            assertThrows(NetworkManagerClientExceptions.NetworkRequestFailed::class.java) {
                openId4VP.shareVerifiablePresentation(vpResponseMetadata)
            }

        assertEquals(expectedValue, networkRequestFailedException.message)
    }

    @Test
    fun `should throw exception if Authorization Response request call takes more time to return response than specified time`() {
        vpResponseMetadata = VPResponseMetadata(
            "eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ",
            "RsaSignature2018",
            publicKey,
            "https://123",
            1000
        )
        expectedValue = "VP sharing failed due to connection timeout"

        val networkRequestFailedException =
            assertThrows(NetworkManagerClientExceptions.NetworkRequestFailedDueToConnectionTimeout::class.java) {
                openId4VP.shareVerifiablePresentation(vpResponseMetadata)
            }

        assertEquals(expectedValue, networkRequestFailedException.message)
    }

    @Test
    fun `should return ok message if Authorization Response request call is made successfully and returned response with http status 200`() {
        val mockResponse: MockResponse = MockResponse().setResponseCode(200)
        mockWebServer.enqueue(mockResponse)
        vpResponseMetadata = VPResponseMetadata(
            "eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ",
            "RsaSignature2018",
            publicKey,
            "https://123",
            3000
        )
        val expectedValue = "OK"

        val actualResponse = openId4VP.shareVerifiablePresentation(vpResponseMetadata)

        assertEquals(expectedValue, actualResponse)
    }
}