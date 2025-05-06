package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPToken
import io.mosip.openID4VP.constants.FormatType
import org.junit.Test
import org.junit.jupiter.api.Assertions.*

class AuthorizationResponseUtilsTest{
    @Test
    fun `should convert the unsignedVPTokens to JSON successfully`() {
        val unsignedLdpVPToken = UnsignedLdpVPToken(
            context = listOf("https://www.w3.org/2018/credentials/v1"),
            type = listOf("VerifiablePresentation"),
            verifiableCredential = listOf("credential1","credential2","credential3"),
            id = "649d581c-f291-4969-9cd5-2c27385a348f",
            holder = "",
        )
        val unsignedVPTokens = mapOf(FormatType.LDP_VC to unsignedLdpVPToken)
        assertEquals(
            "{\"ldp_vc\":{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"type\":[\"VerifiablePresentation\"],\"verifiableCredential\":[\"credential1\",\"credential2\",\"credential3\"],\"id\":\"649d581c-f291-4969-9cd5-2c27385a348f\",\"holder\":\"\"}}",
            unsignedVPTokens.toJsonString()
        )
    }
}