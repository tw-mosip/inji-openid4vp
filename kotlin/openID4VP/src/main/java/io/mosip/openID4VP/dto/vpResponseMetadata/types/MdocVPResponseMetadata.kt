package io.mosip.openID4VP.dto.vpResponseMetadata.types

import io.mosip.openID4VP.dto.vpResponseMetadata.VPResponseMetadata

data class MdocVPResponseMetadata(
    val deviceAuthenticationSignature: Map<String, DeviceAuthentication>
): VPResponseMetadata {
    fun validate(){
        //TODO: Implement validation logic
    }
}

data class DeviceAuthentication(
    val signature: String,
    val algorithm: String
)
//DocType
//Signature
//Algorithm