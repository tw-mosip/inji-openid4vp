package io.mosip.openID4VP.authenticationResponse

import io.mosip.openID4VP.OpenId4VP
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.validatePresentationDefinition
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.dto.Verifier

class AuthenticationResponse {
    companion object{
        fun getAuthenticationResponse(trustedVerifiers: List<Verifier>, openId4VP: OpenId4VP): Map<String,String> {
            val response = mutableMapOf<String,String>()
            validateVerifierClientID(openId4VP.authorizationRequest.clientId, openId4VP.authorizationRequest.responseUri, trustedVerifiers)?.let {
                try {
                    val presentationDefinitionJson = openId4VP.authorizationRequest.presentationDefinition
                    presentationDefinitionJson?.let {
                        val presentationDefinition: PresentationDefinition = validatePresentationDefinition(presentationDefinitionJson)
                        openId4VP.presentationDefinitionId = presentationDefinition.id
                        response.put("presentation_definition", presentationDefinitionJson) }
                    val scope = openId4VP.authorizationRequest.scope
                    scope?.let{
                        response.put("scope",scope)
                    }
                    return response
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