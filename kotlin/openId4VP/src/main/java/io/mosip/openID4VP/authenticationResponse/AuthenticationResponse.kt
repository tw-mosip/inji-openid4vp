package io.mosip.openID4VP.authenticationResponse

import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.validatePresentationDefinition
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.dto.Verifier

data class AuthenticationResponse(val verifier: Verifier, val presentationDefinition: PresentationDefinition) {
    companion object{
        fun getAuthenticationResponse(receivedClientId:String, presentationDefinitionJson: String, responseUri: String, trustedVerifiers: List<Verifier>): AuthenticationResponse {
            validateVerifierClientID(receivedClientId, responseUri, trustedVerifiers)?.let {
                try {
                    val presentationDefinition:PresentationDefinition = validatePresentationDefinition(presentationDefinitionJson)
                    return AuthenticationResponse(it, presentationDefinition)
                }catch (e: Exception) {
                    throw e
                }
            }?:run { throw AuthorizationRequestExceptions.InvalidVerifierClientIDException()}
        }

        private fun validateVerifierClientID(receivedClientId: String, responseUri: String, trustedVerifiers: List<Verifier>): Verifier?{
            return trustedVerifiers.find { it.clientId == receivedClientId && responseUri in it.responseUri}
        }
    }
}