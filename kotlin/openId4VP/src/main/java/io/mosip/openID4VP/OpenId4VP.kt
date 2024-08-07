package io.mosip.openID4VP

import io.mosip.openID4VP.authenticationResponse.AuthenticationResponse
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponse
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.dto.VPResponseMetadata
import io.mosip.openID4VP.dto.Verifier
import java.io.IOException

class OpenId4VP(private val traceabilityId: String){
    lateinit var authorizationRequest: AuthorizationRequest
    lateinit var presentationDefinitionId: String
    private lateinit var authorizationResponse: AuthorizationResponse

    fun authenticateVerifier(encodedAuthorizationRequest: String, trustedVerifiers: List<Verifier>): Map<String,String>{
        try {
            Logger.setTraceability(traceabilityId)
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

    fun shareVerifiablePresentation(vpResponseMetadata: VPResponseMetadata):String{
        try{
            return authorizationResponse.shareVP(vpResponseMetadata, this)
        }catch (exception: IOException){
            throw exception
        }
    }
}