package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp

import com.google.gson.annotations.SerializedName
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken

data class LdpVPToken(
    @SerializedName("@context")
    val context: List<String> = listOf("https://www.w3.org/2018/credentials/v1"),
    val type: List<String> = listOf("VerifiablePresentation"),
    val verifiableCredential: List<Any>,
    val id: String,
    val holder: String,
    val proof: Proof,
) : VPToken {
    companion object {
        const val INTERNAL_PATH: String = "VerifiableCredential"
    }
}