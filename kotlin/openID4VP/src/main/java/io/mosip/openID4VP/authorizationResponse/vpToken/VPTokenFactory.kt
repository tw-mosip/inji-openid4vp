package io.mosip.openID4VP.authorizationResponse.vpToken

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPTokenBuilder
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.LdpVPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc.MdocVPTokenSigningResult

class VPTokenFactory(
    private val vpTokenSigningResult: VPTokenSigningResult,
    private val unsignedVPToken: UnsignedVPToken? =  null,
    private val credentials: List<Any>? =  null,
    private val nonce: String
) {

    fun getVPTokenBuilder(credentialFormat: FormatType): VPTokenBuilder {
        return when (credentialFormat) {
            FormatType.LDP_VC -> LdpVPTokenBuilder(
                ldpVPTokenSigningResult = vpTokenSigningResult as LdpVPTokenSigningResult,
                unsignedLdpVPToken = unsignedVPToken as UnsignedLdpVPToken,
                nonce = nonce
            )
            FormatType.MSO_MDOC -> MdocVPTokenBuilder(
                mdocVPTokenSigningResult = vpTokenSigningResult as MdocVPTokenSigningResult,
                mdocCredentials = credentials as List<String>,
            )
        }
    }
}

