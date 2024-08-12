package io.mosip.openID4VP

import io.mosip.openID4VP.authenticationResponse.AuthenticationResponse
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponse
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.dto.VPResponseMetadata
import io.mosip.openID4VP.dto.Verifier
import java.io.IOException

class OpenId4VP(private val traceabilityId: String) {
    lateinit var authorizationRequest: AuthorizationRequest
    lateinit var presentationDefinitionId: String

    fun authenticateVerifier(
        encodedAuthorizationRequest: String, trustedVerifiers: List<Verifier>
    ): Map<String, String> {
        try {
            Logger.setTraceability(traceabilityId)
            this.authorizationRequest =
                AuthorizationRequest.getAuthorizationRequest(encodedAuthorizationRequest)

            val authenticationResponse =
                AuthenticationResponse.getAuthenticationResponse(trustedVerifiers, this)

            return authenticationResponse
        } catch (exception: Exception) {
            throw exception
        }
    }

    fun constructVerifiablePresentationToken(verifiableCredentials: Map<String, List<String>>): String {
        try {
            return AuthorizationResponse.constructVPTokenForSigning(verifiableCredentials)
        }catch (exception: Exception) {
            throw exception
        }
    }

    fun shareVerifiablePresentation(vpResponseMetadata: VPResponseMetadata): String {
        try {
            return AuthorizationResponse.shareVP(vpResponseMetadata, this)
        } catch (exception: Exception) {
            throw exception
        }
    }
}