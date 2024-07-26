package io.mosip.openID4VP

import io.mosip.openID4VP.authenticationResponse.AuthenticationResponse
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.dto.Verifier

class OpenId4VP (val traceabilityId: String){

    private lateinit var authorizationRequest: AuthorizationRequest

    fun authenticateVerifier(encodedAuthorizationRequest: String, trustedVerifiers: List<Verifier>): AuthenticationResponse{
        try {
            this.authorizationRequest = AuthorizationRequest.getAuthorizationRequest(encodedAuthorizationRequest)

            return AuthenticationResponse.getAuthenticationResponse(this.authorizationRequest.clientId, authorizationRequest.presentationDefinition, authorizationRequest.responseUri, trustedVerifiers)
        }catch (e: Exception){
            throw e
        }
    }
}