package io.mosip.openID4VP.authenticationResponse

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.validatePresentationDefinition
import io.mosip.openID4VP.dto.Verifier

class AuthenticationResponse {
    companion object {
        fun validateVerifierAndPresentationDefinition(
            authorizationRequest: AuthorizationRequest,
            trustedVerifiers: List<Verifier>,
            updatePresentationDefinition: (PresentationDefinition) -> Unit
        ) {
            validateVerifier(
                authorizationRequest.clientId,
                authorizationRequest.responseUri,
                trustedVerifiers
            )?.let {
                try {
                    val presentationDefinitionJson =
                        authorizationRequest.presentationDefinition
                    val presentationDefinition: PresentationDefinition =
                        validatePresentationDefinition(presentationDefinitionJson.toString())
                    updatePresentationDefinition(presentationDefinition)
                } catch (e: Exception) {
                    throw e
                }
            } ?: run { throw AuthorizationRequestExceptions.InvalidVerifierClientID() }
        }

        private fun validateVerifier(
            receivedClientId: String,
            responseUri: String,
            trustedVerifiers: List<Verifier>
        ): Verifier? {
            return trustedVerifiers.find { it.clientId == receivedClientId && responseUri in it.responseUris }
        }
    }
}