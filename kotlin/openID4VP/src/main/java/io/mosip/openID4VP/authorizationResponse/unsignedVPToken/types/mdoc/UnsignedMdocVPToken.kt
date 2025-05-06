package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken

data class UnsignedMdocVPToken(
    val unsignedDeviceAuth: Map<String, String>
) : UnsignedVPToken
