package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp

import com.fasterxml.jackson.annotation.JsonProperty
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken

data class LdpVPToken(
    @JsonProperty("@context")
    val context: List<String> = listOf("https://www.w3.org/2018/credentials/v1"),
    val type: List<String> = listOf("VerifiablePresentation"),
    val verifiableCredential: List<String>,
    val id: String,
    val holder: String,
    val proof: Proof,
) : VPToken {
    companion object {
        const val INTERNAL_PATH: String = "VerifiableCredential"
    }
}