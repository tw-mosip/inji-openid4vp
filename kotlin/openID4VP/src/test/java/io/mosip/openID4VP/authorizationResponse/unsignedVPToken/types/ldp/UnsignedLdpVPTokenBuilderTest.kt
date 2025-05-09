package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.common.encodeToJsonString
import io.mosip.openID4VP.exceptions.Exceptions
import io.mosip.openID4VP.testData.ldpCredential1
import io.mosip.openID4VP.testData.ldpCredential2
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows

class UnsignedLdpVPTokenBuilderTest {

    private val verifiableCredentials = listOf(ldpCredential1, ldpCredential2)
    private val id = "649d581c-f291-4969-9cd5-2c27385a348f"
    private val holder = "did:example:123456789"

    @Before
    fun setUp() {
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
    }

    @Test
    fun `should create UnsignedLdpVPToken with valid input`() {
        val result = UnsignedLdpVPTokenBuilder(
            verifiableCredentials,
            id,
            holder
        ).build() as UnsignedLdpVPToken

        assertNotNull(result)
        assertEquals(listOf("https://www.w3.org/2018/credentials/v1"), result.context)
        assertEquals(listOf("VerifiablePresentation"), result.type)
        assertEquals(verifiableCredentials, result.verifiableCredential)
        assertEquals(id, result.id)
        assertEquals(holder, result.holder)
    }

    @Test
    fun `should return correct JSON representation`() {
        val verifiableCredentials = listOf(ldpCredential1)
        val token = UnsignedLdpVPTokenBuilder(
            verifiableCredentials,
            id,
            holder
        ).build() as UnsignedLdpVPToken

        val expectedJson =
            "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"type\":[\"VerifiablePresentation\"],\"verifiableCredential\":[\"{\\\"format\\\":\\\"ldp_vc\\\",\\\"verifiableCredential\\\":{\\\"credential\\\":{\\\"issuanceDate\\\":\\\"2024-08-02T16:04:35.304Z\\\",\\\"credentialSubject\\\":{\\\"face\\\":\\\"data:image/jpeg;base64,/9j/goKCyuig\\\",\\\"dateOfBirth\\\":\\\"2000/01/01\\\",\\\"id\\\":\\\"did:jwk:eyJr80435=\\\",\\\"UIN\\\":\\\"9012378996\\\",\\\"email\\\":\\\"mockuser@gmail.com\\\"},\\\"id\\\":\\\"https://domain.net/credentials/12345-87435\\\",\\\"proof\\\":{\\\"type\\\":\\\"RsaSignature2018\\\",\\\"created\\\":\\\"2024-04-14T16:04:35Z\\\",\\\"proofPurpose\\\":\\\"assertionMethod\\\",\\\"verificationMethod\\\":\\\"https://domain.net/.well-known/public-key.json\\\",\\\"jws\\\":\\\"eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ\\\"},\\\"type\\\":[\\\"VerifiableCredential\\\"],\\\"@context\\\":[\\\"https://www.w3.org/2018/credentials/v1\\\",\\\"https://domain.net/.well-known/context.json\\\",{\\\"sec\\\":\\\"https://w3id.org/security#\\\"}],\\\"issuer\\\":\\\"https://domain.net/.well-known/issuer.json\\\"}}}\"],\"id\":\"649d581c-f291-4969-9cd5-2c27385a348f\",\"holder\":\"did:example:123456789\"}"
        assertEquals(
            expectedJson,
            encodeToJsonString<UnsignedLdpVPToken>(token, "token", "UnsignedLdpVPToken")
        )
    }

    @Test
    fun `should throw error for empty verifiable credentials list`() {
        val exception = assertThrows<Exceptions.InvalidData> {
            UnsignedLdpVPTokenBuilder(
                emptyList(),
                id,
                holder
            ).build() as UnsignedLdpVPToken
        }
        assertEquals("Ldp Verifiable Credential List is empty", exception.message)

    }
}
