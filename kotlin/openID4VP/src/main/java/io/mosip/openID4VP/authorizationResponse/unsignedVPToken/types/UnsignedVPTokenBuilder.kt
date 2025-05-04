package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken

interface UnsignedVPTokenBuilder {
    fun build(): UnsignedVPToken
}