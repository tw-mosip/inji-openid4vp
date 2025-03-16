package io.mosip.openID4VP.authorizationResponse.models

import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.VPTokensForSigning
import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.toJsonString
import io.mosip.openID4VP.testData.vpTokensForSigning
import org.junit.Test
import org.junit.jupiter.api.Assertions.assertEquals

class VPTokensForSigningTest {
    @Test
    fun `should convert the vpTokensForSigning to JSON successfully`() {
        val vpTokensForSigning: VPTokensForSigning = vpTokensForSigning

        assertEquals("{\"ldp_vc\":{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"type\":[\"VerifiablePresentation\"],\"verifiableCredential\":[\"credential1\",\"credential2\",\"credential3\"],\"id\":\"649d581c-f291-4969-9cd5-2c27385a348f\",\"holder\":\"\"}}", vpTokensForSigning.toJsonString())
    }
}