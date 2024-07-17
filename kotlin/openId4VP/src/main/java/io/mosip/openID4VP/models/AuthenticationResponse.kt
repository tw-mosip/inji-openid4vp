package io.mosip.openID4VP.models

data class AuthenticationResponse(val verifier: Verifier, val presentationDefinition: PresentationDefinition)