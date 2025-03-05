package io.mosip.openID4VP.authorizationResponse.models.vpToken.types

import io.mosip.openID4VP.authorizationResponse.Proof
import io.mosip.openID4VP.authorizationResponse.models.vpToken.VPToken
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

data class LdpVPToken(
    @SerialName("@context") val context: List<String> = listOf("https://www.w3.org/2018/credentials/v1"),
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