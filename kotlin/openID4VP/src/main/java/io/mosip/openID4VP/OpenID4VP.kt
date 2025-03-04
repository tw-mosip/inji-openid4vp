package io.mosip.openID4VP

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponse
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.dto.VPResponseMetadata
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest

private val logTag = Logger.getLogTag(AuthorizationResponse::class.simpleName!!)
class OpenID4VP(private val traceabilityId: String) {
    lateinit var authorizationRequest: AuthorizationRequest
    private var responseUri: String? = null

    private fun setResponseUri(responseUri: String) {
        this.responseUri = responseUri
    }

    @JvmOverloads
    fun authenticateVerifier(
        urlEncodedAuthorizationRequest: String,
        trustedVerifiers: List<Verifier>,
        shouldValidateClient: Boolean = false
    ): AuthorizationRequest {
        try {
            Logger.setTraceabilityId(traceabilityId)
            authorizationRequest = AuthorizationRequest.validateAndCreateAuthorizationRequest(
                urlEncodedAuthorizationRequest, trustedVerifiers, ::setResponseUri,shouldValidateClient
            )
            return this.authorizationRequest
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
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    fun shareVerifiablePresentation(vpResponseMetadata: VPResponseMetadata): String {
        try {
            //TODO: fix this
            return AuthorizationResponse.shareVP(
                vpResponseMetadata,
                authorizationRequest,
                responseUri ?: "http://localhost:8080/injiverify.dev2.mosip.net/redirect"
            )
        } catch (exception: Exception) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    fun sendErrorToVerifier(exception: Exception) {
        responseUri?.let {
            try {
                sendHTTPRequest(
                    url = it, method = HTTP_METHOD.POST,mapOf("error" to exception.message!!)
                )
            } catch (exception: Exception) {
                Logger.error(
                    logTag,
                    Exception("Unexpected error occurred while sending the error to verifier: ${exception.message}")
                )
            }
        }
    }
}