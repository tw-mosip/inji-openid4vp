package io.mosip.openID4VP.models

data class AuthorizationRequest(
    val clientId: String,
    val responseType: String,
    val responseMode: String,
    val presentationDefinition: PresentationDefinition,
    val responseUri: String,
    val nonce: String,
    val state: String
)
