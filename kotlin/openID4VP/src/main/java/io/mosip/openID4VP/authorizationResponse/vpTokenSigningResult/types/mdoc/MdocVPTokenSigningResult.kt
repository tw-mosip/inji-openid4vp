package io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc

import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult

class MdocVPTokenSigningResult(
    val deviceAuthenticationSignature: Map<String, DeviceAuthentication>
) : VPTokenSigningResult {
    fun validate() {
        deviceAuthenticationSignature.map { (_, deviceAuthentication) ->
            deviceAuthentication.validate()
        }
    }
}