package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldpVp

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.UnsignedLdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.authenticationContainer.types.LdpAuthenticationContainer

class LdpVPTokenBuilder(
    val ldpAuthenticationContainer: LdpAuthenticationContainer,
    val unsignedLdpVPToken: UnsignedLdpVPToken,
    val nonce: String
) : VPTokenBuilder {
    override fun build(): LdpVPToken {
        ldpAuthenticationContainer.validate()
        val proof = Proof.construct(
            ldpAuthenticationContainer, challenge = nonce
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