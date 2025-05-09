package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp

import io.mockk.mockk
import io.mockk.verify
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.LdpVPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPToken
import io.mosip.openID4VP.testData.unsignedLdpVPToken
import org.junit.Test
import org.junit.jupiter.api.Assertions.*


class LdpVPTokenBuilderTest {
    private val mockLdpVPTokenSigningResult = mockk<LdpVPTokenSigningResult>(relaxed = true)


    @Test
    fun `should build LdpVPToken with valid inputs`() {
        val nonce = "test-nonce-value"


        val result = LdpVPTokenBuilder(mockLdpVPTokenSigningResult, unsignedLdpVPToken, nonce).build()

        assertEquals(unsignedLdpVPToken.context, result.context)
        assertEquals(unsignedLdpVPToken.type, result.type)
        assertEquals(unsignedLdpVPToken.verifiableCredential, result.verifiableCredential)
        assertEquals(unsignedLdpVPToken.id, result.id)
        assertEquals(unsignedLdpVPToken.holder, result.holder)
        assertNotNull(result.proof)
    }

    @Test
    fun `should pass proper challenge to proof constructor`() {
        val unsignedToken = UnsignedLdpVPToken(
            context = listOf("https://www.w3.org/2018/credentials/v1"),
            type = listOf("VerifiablePresentation"),
            verifiableCredential = listOf("credential"),
            id = "test-id",
            holder = "test-holder"
        )
        val nonce = "specific-test-nonce"

        val result = LdpVPTokenBuilder(mockLdpVPTokenSigningResult, unsignedToken, nonce).build()

        assertEquals(nonce, result.proof.challenge)
    }

    @Test
    fun `should validate LdpVPTokenSigningResult when building token`() {
        val unsignedToken = UnsignedLdpVPToken(
            context = listOf("https://www.w3.org/2018/credentials/v1"),
            type = listOf("VerifiablePresentation"),
            verifiableCredential = emptyList(),
            id = "test-id",
            holder = "test-holder"
        )
        LdpVPTokenBuilder(mockLdpVPTokenSigningResult, unsignedToken, "nonce").build()
        verify {
            mockLdpVPTokenSigningResult.validate()
        }
    }
}
