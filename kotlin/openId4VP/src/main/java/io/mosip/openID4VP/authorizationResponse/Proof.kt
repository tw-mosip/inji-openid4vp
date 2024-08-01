package io.mosip.openID4VP.authorizationResponse

data class Proof(
    val type: String,
    val created: String,
    val challenge: String,
    val domain: String,
    val jws: String,
    val proofPurpose: String,
    val verificationMethod: String
)