package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldpVp

import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken
import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.types.LdpVPTokenForSigning
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenBuilder
import io.mosip.openID4VP.dto.VPResponseMetadata.types.LdpVPResponseMetadata

class LdpVPTokenBuilder(
    val ldpVPResponseMetadata: LdpVPResponseMetadata,
    val ldpVPTokenForSigning: LdpVPTokenForSigning,
    val nonce: String
) : VPTokenBuilder {
    override fun build(): VPToken {
        ldpVPResponseMetadata.validate()
        val proof = Proof.constructProof(
            ldpVPResponseMetadata, challenge = nonce
        )

        return LdpVPToken(
            ldpVPTokenForSigning.context,
            ldpVPTokenForSigning.type,
            ldpVPTokenForSigning.verifiableCredential,
            ldpVPTokenForSigning.id,
            ldpVPTokenForSigning.holder,
            proof
        )
    }
}