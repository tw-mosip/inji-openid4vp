package io.mosip.openID4VP.authorizationResponse.presentationSubmission

import io.mosip.openID4VP.authorizationResponse.Proof

data class VPToken (
    val context: List<String> = listOf("https://www.w3.org/2018/credentials/v1"),
    val type: List<String> = listOf("VerifiablePresentation"),
    val verifiableCredential: List<String>,
    val id: String,
    val holder: String,
    val proof: Proof
)