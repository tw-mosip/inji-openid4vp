package io.mosip.openID4VP.authorizationResponse.vpToken

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.UnsignedLdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldpVp.LdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPTokenBuilder
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.authorizationResponse.authenticationContainer.AuthenticationContainer
import io.mosip.openID4VP.authorizationResponse.authenticationContainer.types.LdpAuthenticationContainer
import io.mosip.openID4VP.authorizationResponse.authenticationContainer.types.MdocAuthenticationContainer

class VPTokenFactory(
    private val authenticationContainer: AuthenticationContainer,
    private val unsignedVpToken: UnsignedVPToken? =  null,
    private val credentials: List<Any>? =  null,
    private val nonce: String
) {

    fun getVPTokenBuilder(credentialFormat: FormatType): VPTokenBuilder {
        return when (credentialFormat) {
            FormatType.LDP_VC -> LdpVPTokenBuilder(
                ldpAuthenticationContainer = authenticationContainer as LdpAuthenticationContainer,
                unsignedLdpVPToken = unsignedVpToken as UnsignedLdpVPToken,
                nonce = nonce
            )
            FormatType.MSO_MDOC -> MdocVPTokenBuilder(
                mdocAuthenticationContainer = authenticationContainer as MdocAuthenticationContainer,
                mdocCredentials = credentials as List<String>,
            )
        }
    }
}

