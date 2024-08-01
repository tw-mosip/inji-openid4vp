package io.mosip.openID4VP

import io.mosip.openID4VP.authenticationResponse.AuthenticationResponse
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponse
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.VPTokenForSigning
import io.mosip.openID4VP.dto.Verifier
import okhttp3.Response
import java.security.PublicKey

class OpenId4VP (val traceabilityId: String){

    lateinit var authorizationRequest: AuthorizationRequest
    lateinit var presentationDefinitionId: String
    lateinit var authorizationResponse: AuthorizationResponse

    fun authenticateVerifier(encodedAuthorizationRequest: String, trustedVerifiers: List<Verifier>): Map<String,String>{
        try {
            this.authorizationRequest = AuthorizationRequest.getAuthorizationRequest(encodedAuthorizationRequest)

            val authenticationResponse = AuthenticationResponse.getAuthenticationResponse(trustedVerifiers, this)

            return authenticationResponse
        }catch (e: Exception){
            throw e
        }
    }

    fun constructVPToken(selectedVerifiableCredentials: Map<String, List<String>>): String {
        authorizationResponse = AuthorizationResponse()
        return authorizationResponse.constructVPTokenForSigning(selectedVerifiableCredentials)
    }

    fun shareVerifiablePresentation(jws: String, signatureAlgoType: String, publicKey: String, domain: String):Response{
       return authorizationResponse.shareVP(jws, signatureAlgoType, publicKey, domain, this)
    }
}