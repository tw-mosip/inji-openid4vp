package io.mosip.openID4VP

import io.mosip.openID4VP.authenticationResponse.AuthenticationResponse
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponse
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.dto.VPResponseMetadata
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHttpPostRequest
import okhttp3.ResponseBody.Companion.toResponseBody

class OpenId4VP(private val traceabilityId: String) {
    lateinit var authorizationRequest: AuthorizationRequest
    lateinit var presentationDefinitionId: String
    var responseUri: String? = null
    private lateinit var logTag: String

    fun authenticateVerifier(
        encodedAuthorizationRequest: String, trustedVerifiers: List<Verifier>
    ): Map<String, String> {
        try {
            Logger.setTraceability(traceabilityId)
            logTag = Logger.getLogTag(AuthorizationRequest::class.simpleName!!)
            authorizationRequest = AuthorizationRequest.getAuthorizationRequest(
                encodedAuthorizationRequest, this
            )
            return AuthenticationResponse.getAuthenticationResponse(
                trustedVerifiers, this
            )
        } catch (exception: Exception) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    fun constructVerifiablePresentationToken(verifiableCredentials: Map<String, List<String>>): String {
        try {
            return AuthorizationResponse.constructVPTokenForSigning(
                verifiableCredentials
            )
        } catch (exception: Exception) {
            throw exception
        }
    }

    fun shareVerifiablePresentation(vpResponseMetadata: VPResponseMetadata): String {
        try {
            return AuthorizationResponse.shareVP(vpResponseMetadata, this)
        } catch (exception: Exception) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    private fun sendErrorToVerifier(exception: Exception) {
        responseUri?.let {
            try {
                val response = sendHttpPostRequest(
                    it, mapOf("error" to exception.message!!)
                )

                println("verifier call response::${response.toResponseBody()}")
            } catch (exception: Exception) {
                Logger.error(
                    logTag,
                    Exception("Unexpected error occurred while sending the error to verifier.")
                )
            }
        }
    }
}