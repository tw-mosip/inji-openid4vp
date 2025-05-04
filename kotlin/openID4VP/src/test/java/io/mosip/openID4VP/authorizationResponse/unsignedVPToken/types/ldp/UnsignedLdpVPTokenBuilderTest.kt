package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp

import io.mosip.openID4VP.common.encodeToJsonString
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UnsignedLdpVPTokenBuilderTest {

    private val verifiableCredentials = listOf("VC1", "VC2", "VC3")
    private val id = "649d581c-f291-4969-9cd5-2c27385a348f"
    private val holder = "did:example:123456789"

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
        val token = UnsignedLdpVPTokenBuilder(
            verifiableCredentials,
            id,
            holder
        ).build() as UnsignedLdpVPToken

        val expectedJson =
            "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"type\":[\"VerifiablePresentation\"],\"verifiableCredential\":[\"VC1\",\"VC2\",\"VC3\"],\"id\":\"649d581c-f291-4969-9cd5-2c27385a348f\",\"holder\":\"did:example:123456789\"}"
        assertEquals(
            expectedJson,
            encodeToJsonString<UnsignedLdpVPToken>(token, "token", "UnsignedLdpVPToken")
        )
    }

    @Test
    fun `should handle empty verifiable credentials list`() {
        val result = UnsignedLdpVPTokenBuilder(
            emptyList(),
            id,
            holder
        ).build() as UnsignedLdpVPToken

        assertNotNull(result)
        assertTrue(result.verifiableCredential.isEmpty())
    }
}
