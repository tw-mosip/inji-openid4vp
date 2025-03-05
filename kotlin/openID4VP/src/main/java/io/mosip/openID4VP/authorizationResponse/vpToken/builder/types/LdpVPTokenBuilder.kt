package io.mosip.openID4VP.authorizationResponse.vpToken.builder.types

import io.mosip.openID4VP.authorizationResponse.Proof
import io.mosip.openID4VP.authorizationResponse.models.vpToken.VPToken
import io.mosip.openID4VP.authorizationResponse.models.vpToken.types.LdpVPToken
import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.types.LdpVPTokenForSigning
import io.mosip.openID4VP.authorizationResponse.vpToken.builder.VPTokenBuilder
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