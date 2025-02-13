package io.mosip.openID4VP.authorizationResponse.models.vpToken.types

import io.mosip.openID4VP.authorizationResponse.Proof
import io.mosip.openID4VP.authorizationResponse.models.vpToken.CredentialFormatSpecificVPToken
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class LdpVPToken(
    @SerialName("@context") val context: List<String> = listOf("https://www.w3.org/2018/credentials/v1"),
    val type: List<String> = listOf("VerifiablePresentation"),
    val verifiableCredential: List<String>,
    val id: String,
    val holder: String,
    val proof: Proof,
    override val dataType: String = "LdpVP",
) : CredentialFormatSpecificVPToken {
    companion object {
        const val internalPath: String = "VerifiableCredential"
    }
}