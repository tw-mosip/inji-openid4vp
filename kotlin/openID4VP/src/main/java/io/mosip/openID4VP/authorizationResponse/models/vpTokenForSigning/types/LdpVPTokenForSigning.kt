package io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.types

import com.fasterxml.jackson.annotation.JsonProperty
import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.VPTokenForSigning

data class LdpVPTokenForSigning(
    @JsonProperty("@context")
    val context: List<String> = listOf("https://www.w3.org/2018/credentials/v1"),
    val type: List<String> = listOf("VerifiablePresentation"),
    val verifiableCredential: List<String>,
    val id: String,
    val holder: String,
): VPTokenForSigning
