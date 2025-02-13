package io.mosip.openID4VP.authorizationResponse.vpToken

import io.mosip.openID4VP.authorizationResponse.exception.AuthorizationResponseExceptions
import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.CredentialFormatSpecificSigningData
import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.types.LdpVpSpecificSigningData
import io.mosip.openID4VP.authorizationResponse.vpToken.builder.VPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.builder.types.LdpVPTokenBuilder
import io.mosip.openID4VP.common.FormatType
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.dto.VPResponseMetadata.VPResponseMetadata
import io.mosip.openID4VP.dto.VPResponseMetadata.types.LdpVPResponseMetadata

private val  className = VPTokenFactory::class.java.simpleName

class VPTokenFactory(
    private val vpResponseMetadata: VPResponseMetadata,
    private val vpTokenForSigning: CredentialFormatSpecificSigningData,
    private val nonce: String
) {

    fun getVPTokenBuilder(credentialFormat: FormatType): VPTokenBuilder {
        return when (credentialFormat) {
            FormatType.ldp_vc -> LdpVPTokenBuilder(
                ldpVPResponseMetadata = vpResponseMetadata as LdpVPResponseMetadata,
                ldpVPTokenForSigning = vpTokenForSigning as LdpVpSpecificSigningData,
                nonce = nonce
            )
            else -> throw Logger.handleException(
                exceptionType = "unsupportedFormatOfLibrary",
                className = className
            )
        }
    }
}

