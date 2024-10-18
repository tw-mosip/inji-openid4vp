package io.mosip.openID4VP.authenticationResponse

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
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
                        deserializeAndValidate(
                            presentationDefinitionJson.toString(),
                            PresentationDefinitionSerializer
                        )
                    updatePresentationDefinition(presentationDefinition)
                } catch (e: Exception) {
                    throw e
                }
            } ?: run { throw AuthorizationRequestExceptions.InvalidVerifierClientID() }
        }

        private fun validateVerifier(
            receivedClientId: String,
            receivedResponseUri: String,
            trustedVerifiers: List<Verifier>
        ): Verifier? {
            return trustedVerifiers.find { it.clientId == receivedClientId && receivedResponseUri in it.responseUris }
        }
    }
}