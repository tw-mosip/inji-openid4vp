package io.mosip.openID4VP.authorizationResponse.vpToken

import io.mosip.openID4VP.authorizationResponse.models.vpToken.CredentialFormatSpecificVPToken
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
sealed class VPTokenType {
    @Serializable
    @SerialName("VPTokenArray")
    data class VPTokenArray(val value: List<CredentialFormatSpecificVPToken>) : VPTokenType()

    @Serializable
    @SerialName("VPToken")
    data class VPToken(val value: CredentialFormatSpecificVPToken) : VPTokenType()
}