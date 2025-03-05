package io.mosip.openID4VP.authorizationResponse.vpToken

sealed class VPTokenType {
    data class VPTokenArray(val value: List<io.mosip.openID4VP.authorizationResponse.models.vpToken.VPToken>) : VPTokenType()

    data class VPToken(val value: io.mosip.openID4VP.authorizationResponse.models.vpToken.VPToken) : VPTokenType()
}
