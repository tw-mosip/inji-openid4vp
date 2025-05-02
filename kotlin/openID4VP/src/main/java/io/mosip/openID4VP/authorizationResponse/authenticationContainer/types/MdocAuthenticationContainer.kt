package io.mosip.openID4VP.authorizationResponse.authenticationContainer.types

import io.mosip.openID4VP.authorizationResponse.authenticationContainer.AuthenticationContainer

data class MdocAuthenticationContainer(
    val deviceAuthenticationSignature: Map<String, DeviceAuthentication>
): AuthenticationContainer {
    fun validate(){
        //TODO: Implement validation logic
    }
}

data class DeviceAuthentication(
    val signature: String,
    val algorithm: String
)
