package io.mosip.openID4VP.authenticationResponse

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.validatePresentationDefinition
import io.mosip.openID4VP.dto.Verifier

class AuthenticationResponse {
    companion object {
        fun getAuthenticationResponse(
            authorizationRequest: AuthorizationRequest,
            trustedVerifiers: List<Verifier>,
            setPresentationDefinitionId: (String) -> Unit
        ): Map<String, String> {
            val response = mutableMapOf<String, String>()
            validateVerifierClientID(
                authorizationRequest.clientId,
                authorizationRequest.responseUri,
                trustedVerifiers
            )?.let {
                try {
                    val presentationDefinitionJson =
                        authorizationRequest.presentationDefinition
                    presentationDefinitionJson?.let {
                        val presentationDefinition: PresentationDefinition =
                            validatePresentationDefinition(presentationDefinitionJson)
                        setPresentationDefinitionId(presentationDefinition.id)
                        response.put("presentation_definition", presentationDefinitionJson)
                    }
                    return response
                } catch (e: Exception) {
                    throw e
                }
            } ?: run { throw AuthorizationRequestExceptions.InvalidVerifierClientID() }
        }

        private fun validateVerifierClientID(
            receivedClientId: String,
            responseUri: String,
            trustedVerifiers: List<Verifier>
        ): Verifier? {
            return trustedVerifiers.find { it.clientId == receivedClientId && responseUri in it.responseUris }
        }
    }
}