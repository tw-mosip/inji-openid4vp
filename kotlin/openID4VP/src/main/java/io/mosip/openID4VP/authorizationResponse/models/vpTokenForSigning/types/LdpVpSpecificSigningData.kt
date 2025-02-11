package io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.types

import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.CredentialFormatSpecificSigningData
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

@Serializable
data class LdpVpSpecificSigningData(
    @SerialName("@context") val context: List<String> = listOf("https://www.w3.org/2018/credentials/v1"),
    val type: List<String> = listOf("VerifiablePresentation"),
    val verifiableCredential: List<String>,
    val id: String,
    val holder: String,
    override val dataType: String = "LdpVpSpecificSigningData"
): CredentialFormatSpecificSigningData
