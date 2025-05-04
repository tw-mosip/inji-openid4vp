package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp

import com.fasterxml.jackson.annotation.JsonProperty
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken

data class UnsignedLdpVPToken(
    @JsonProperty("@context")
    val context: List<String> ,
    val type: List<String>,
    val verifiableCredential: List<String>,
    val id: String,
    val holder: String,
): UnsignedVPToken
