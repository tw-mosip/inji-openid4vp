package io.mosip.openID4VP.authorizationResponse.vpToken

import io.mosip.openID4VP.authorizationResponse.models.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.models.unsignedVPToken.types.UnsignedLdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldpVp.LdpVPTokenBuilder
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.dto.vpResponseMetadata.VPResponseMetadata
import io.mosip.openID4VP.dto.vpResponseMetadata.types.LdpVPResponseMetadata

class VPTokenFactory(
    private val vpResponseMetadata: VPResponseMetadata,
    private val unsignedVpToken: UnsignedVPToken,
    private val nonce: String
) {

    fun getVPTokenBuilder(credentialFormat: FormatType): VPTokenBuilder {
        return when (credentialFormat) {
            FormatType.LDP_VC -> LdpVPTokenBuilder(
                ldpVPResponseMetadata = vpResponseMetadata as LdpVPResponseMetadata,
                unsignedLdpVPToken = unsignedVpToken as UnsignedLdpVPToken,
                nonce = nonce
            )
        }
    }
}

