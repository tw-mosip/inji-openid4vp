package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp

import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.LdpVPTokenSigningResult

class LdpVPTokenBuilder(
    val ldpVPTokenSigningResult: LdpVPTokenSigningResult,
    val unsignedLdpVPToken: LdpVPToken,
    val nonce: String
) : VPTokenBuilder {
    override fun build(): LdpVPToken {
        ldpVPTokenSigningResult.validate()

        val ldpVPToken = LdpVPToken(
            unsignedLdpVPToken.context,
            unsignedLdpVPToken.type,
            unsignedLdpVPToken.verifiableCredential,
            unsignedLdpVPToken.id,
            unsignedLdpVPToken.holder,
            unsignedLdpVPToken.proof.apply {
                jws = ldpVPTokenSigningResult.jws
            }
        )

        println("LdpVPTokenBuilder Proof of ldpVPToken: ${ldpVPToken.proof}")
        return ldpVPToken
    }
}