package io.mosip.openID4VP.authorizationResponse.presentationSubmission

import io.mosip.openID4VP.authorizationResponse.Proof
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class VPToken(
    @SerialName("@context") val context: List<String> = listOf("https://www.w3.org/2018/credentials/v1"),
    val type: List<String> = listOf("VerifiablePresentation"),
    val verifiableCredential: List<String>,
    val id: String,
    val holder: String,
    val proof: Proof
) {
    companion object {
        fun constructVpToken(signingVPToken: VPTokenForSigning, proof: Proof): VPToken {
            return VPToken(
                signingVPToken.context,
                signingVPToken.type,
                signingVPToken.verifiableCredential,
                signingVPToken.id,
                signingVPToken.holder,
                proof
            )
        }
    }
}