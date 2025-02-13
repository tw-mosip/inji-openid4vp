package io.mosip.openID4VP.authorizationResponse.vpToken.builder

import io.mosip.openID4VP.authorizationResponse.models.vpToken.CredentialFormatSpecificVPToken

interface VPTokenBuilder {
    fun build(): CredentialFormatSpecificVPToken
}