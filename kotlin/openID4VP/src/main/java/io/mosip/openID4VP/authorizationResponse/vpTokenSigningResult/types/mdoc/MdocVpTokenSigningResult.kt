package io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc

import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VpTokenSigningResult

class MdocVpTokenSigningResult(
    val deviceAuthenticationSignature: Map<String, DeviceAuthentication>
) : VpTokenSigningResult {
    fun validate() {
        deviceAuthenticationSignature.map { (_, deviceAuthentication) ->
            deviceAuthentication.validate()
        }
    }
}