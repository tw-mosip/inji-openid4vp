package io.mosip.openID4VP.authorizationResponse.vpToken.builder

import io.mosip.openID4VP.authorizationResponse.models.vpToken.VPToken

interface VPTokenBuilder {
    fun build(): VPToken
}