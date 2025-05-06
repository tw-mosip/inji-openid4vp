package io.mosip.openID4VP.authorizationResponse.authenticationContainer.types.mdoc

import io.mosip.openID4VP.authorizationResponse.authenticationContainer.AuthenticationContainer

class MdocAuthenticationContainer(
    val deviceAuthenticationSignature: Map<String, DeviceAuthentication>
) : AuthenticationContainer {
    fun validate() {
        deviceAuthenticationSignature.map { (_, deviceAuthentication) ->
            deviceAuthentication.validate()
        }
    }
}