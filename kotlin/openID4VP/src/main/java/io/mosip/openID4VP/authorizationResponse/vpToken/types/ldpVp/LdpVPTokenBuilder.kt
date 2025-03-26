package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldpVp

import io.mosip.openID4VP.authorizationResponse.models.unsignedVPToken.types.UnsignedLdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenBuilder
import io.mosip.openID4VP.dto.vpResponseMetadata.types.LdpVPResponseMetadata

class LdpVPTokenBuilder(
    val ldpVPResponseMetadata: LdpVPResponseMetadata,
    val unsignedLdpVPToken: UnsignedLdpVPToken,
    val nonce: String
) : VPTokenBuilder {
    override fun build(): LdpVPToken {
        ldpVPResponseMetadata.validate()
        val proof = Proof.construct(
            ldpVPResponseMetadata, challenge = nonce
        )

        return LdpVPToken(
            unsignedLdpVPToken.context,
            unsignedLdpVPToken.type,
            unsignedLdpVPToken.verifiableCredential,
            unsignedLdpVPToken.id,
            unsignedLdpVPToken.holder,
            proof
        )
    }
}