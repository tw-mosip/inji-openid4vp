package io.mosip.openID4VP.authorizationResponse.vpToken

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPTokenBuilder
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VpTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.LdpVpTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc.MdocVpTokenSigningResult

class VPTokenFactory(
    private val vpTokenSigningResult: VpTokenSigningResult,
    private val unsignedVpToken: UnsignedVPToken? =  null,
    private val credentials: List<Any>? =  null,
    private val nonce: String
) {

    fun getVPTokenBuilder(credentialFormat: FormatType): VPTokenBuilder {
        return when (credentialFormat) {
            FormatType.LDP_VC -> LdpVPTokenBuilder(
                ldpVpTokenSigningResult = vpTokenSigningResult as LdpVpTokenSigningResult,
                unsignedLdpVPToken = unsignedVpToken as UnsignedLdpVPToken,
                nonce = nonce
            )
            FormatType.MSO_MDOC -> MdocVPTokenBuilder(
                mdocVpTokenSigningResult = vpTokenSigningResult as MdocVpTokenSigningResult,
                mdocCredentials = credentials as List<String>,
            )
        }
    }
}

