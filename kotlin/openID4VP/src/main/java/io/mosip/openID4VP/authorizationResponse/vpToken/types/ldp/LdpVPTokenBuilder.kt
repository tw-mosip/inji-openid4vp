package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.LdpVPTokenSigningResult

class LdpVPTokenBuilder(
    val ldpVPTokenSigningResult: LdpVPTokenSigningResult,
    val unsignedLdpVPToken: UnsignedLdpVPToken,
    val nonce: String
) : VPTokenBuilder {
    override fun build(): LdpVPToken {
        ldpVPTokenSigningResult.validate()
        val proof = Proof.construct(
            ldpVPTokenSigningResult, challenge = nonce
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