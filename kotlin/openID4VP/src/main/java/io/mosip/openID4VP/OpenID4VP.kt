package io.mosip.openID4VP

import io.mosip.openID4VP.authenticationResponse.AuthenticationResponse
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponse
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.dto.VPResponseMetadata
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHttpPostRequest
import okhttp3.ResponseBody.Companion.toResponseBody

private val logTag = Logger.getLogTag(AuthorizationResponse::class.simpleName!!)
class OpenID4VP(private val traceabilityId: String) {
    lateinit var authorizationRequest: AuthorizationRequest
    private lateinit var presentationDefinitionId: String
    private var responseUri: String? = null

    fun setResponseUri(responseUri: String) {
        this.responseUri = responseUri
    }

    fun setPresentationDefinitionId(id: String) {
        this.presentationDefinitionId = id
    }

    fun authenticateVerifier(
        encodedAuthorizationRequest: String, trustedVerifiers: List<Verifier>
    ): AuthorizationRequest {
        try {
            Logger.setTraceability(traceabilityId)
            authorizationRequest = AuthorizationRequest.getAuthorizationRequest(
                encodedAuthorizationRequest, ::setResponseUri
            )
            return AuthenticationResponse.getAuthenticationResponse(
                authorizationRequest, trustedVerifiers, ::setPresentationDefinitionId
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
            return AuthorizationResponse.shareVP(
                vpResponseMetadata,
                authorizationRequest.nonce,
                authorizationRequest.responseUri,
                presentationDefinitionId
            )
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