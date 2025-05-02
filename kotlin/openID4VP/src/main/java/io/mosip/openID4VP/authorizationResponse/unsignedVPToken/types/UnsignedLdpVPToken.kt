package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonRawValue
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken

data class UnsignedLdpVPToken(
    @JsonProperty("@context")
    val context: List<String> = listOf("https://www.w3.org/2018/credentials/v1"),
    val type: List<String> = listOf("VerifiablePresentation"),
    val verifiableCredential: List<String>,
    val id: String,
    val holder: String,
): UnsignedVPToken
