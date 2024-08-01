package io.mosip.openID4VP

import io.mosip.openID4VP.authenticationResponse.AuthenticationResponse
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponse
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.VPTokenForSigning
import io.mosip.openID4VP.dto.Verifier

class OpenId4VP (val traceabilityId: String){

    lateinit var authorizationRequest: AuthorizationRequest
    lateinit var presentationDefinitionId: String


    fun authenticateVerifier(encodedAuthorizationRequest: String, trustedVerifiers: List<Verifier>): Map<String,String>{
        try {
            this.authorizationRequest = AuthorizationRequest.getAuthorizationRequest(encodedAuthorizationRequest)

            val authenticationResponse = AuthenticationResponse.getAuthenticationResponse(trustedVerifiers, this)

            return authenticationResponse
        }catch (e: Exception){
            throw e
        }
    }

    fun constructVerifiablePresentationToken(selectedVerifiableCredentials: Map<String, List<String>>): String {
        return AuthorizationResponse.constructVPToken(selectedVerifiableCredentials)
    }
}