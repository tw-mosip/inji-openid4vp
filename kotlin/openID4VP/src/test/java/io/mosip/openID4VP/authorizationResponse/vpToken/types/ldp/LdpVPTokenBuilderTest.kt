package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp

import io.mockk.mockkClass
import io.mockk.verify
import io.mosip.openID4VP.authorizationResponse.authenticationContainer.types.ldp.LdpAuthenticationContainer
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPToken
import io.mosip.openID4VP.testData.ldpCredential1
import io.mosip.openID4VP.testData.ldpCredential2
import io.mosip.openID4VP.testData.unsignedLdpVPToken
import org.junit.Test
import org.junit.jupiter.api.Assertions.*


class LdpVPTokenBuilderTest {
    private val mockAuthContainer = io.mockk.mockk<LdpAuthenticationContainer>(relaxed = true)


    @Test
    fun `should build LdpVPToken with valid inputs`() {
        val nonce = "test-nonce-value"


        val result = LdpVPTokenBuilder(mockAuthContainer, unsignedLdpVPToken, nonce).build()

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

        val result = LdpVPTokenBuilder(mockAuthContainer, unsignedToken, nonce).build()

        assertEquals(nonce, result.proof.challenge)
    }

    @Test
    fun `should validate ldpAuthenticationContainer when building token`() {
        val mockAuthContainer = io.mockk.mockk<LdpAuthenticationContainer>(relaxed = true)
        val unsignedToken = UnsignedLdpVPToken(
            context = listOf("https://www.w3.org/2018/credentials/v1"),
            type = listOf("VerifiablePresentation"),
            verifiableCredential = emptyList(),
            id = "test-id",
            holder = "test-holder"
        )
        LdpVPTokenBuilder(mockAuthContainer, unsignedToken, "nonce").build()
        verify {
            mockAuthContainer.validate()
        }
    }
}
