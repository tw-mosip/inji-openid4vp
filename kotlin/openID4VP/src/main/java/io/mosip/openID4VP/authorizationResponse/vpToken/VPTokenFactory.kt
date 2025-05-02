package io.mosip.openID4VP.authorizationResponse.vpToken

import io.mosip.openID4VP.authorizationResponse.models.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.models.unsignedVPToken.types.UnsignedLdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldpVp.LdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPTokenBuilder
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.dto.vpResponseMetadata.VPResponseMetadata
import io.mosip.openID4VP.dto.vpResponseMetadata.types.LdpVPResponseMetadata
import io.mosip.openID4VP.dto.vpResponseMetadata.types.MdocVPResponseMetadata

class VPTokenFactory(
    private val vpResponseMetadata: VPResponseMetadata,
    private val unsignedVpToken: UnsignedVPToken? =  null,
    private val credentials: List<Any>? =  null,
    private val nonce: String
) {

    fun getVPTokenBuilder(credentialFormat: FormatType): VPTokenBuilder {
        return when (credentialFormat) {
            FormatType.LDP_VC -> LdpVPTokenBuilder(
                ldpVPResponseMetadata = vpResponseMetadata as LdpVPResponseMetadata,
                unsignedLdpVPToken = unsignedVpToken as UnsignedLdpVPToken,
                nonce = nonce
            )
            FormatType.MSO_MDOC -> MdocVPTokenBuilder(
                mdocVPResponseMetadata = vpResponseMetadata as MdocVPResponseMetadata,
                mdocCredentials = credentials as List<String>,
            )
        }
    }
}

