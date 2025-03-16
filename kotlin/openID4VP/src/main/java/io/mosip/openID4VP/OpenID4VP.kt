package io.mosip.openID4VP

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponseHandler
import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.VPTokenForSigning
import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.VPTokensForSigning
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.dto.VPResponseMetadata.VPResponsesMetadata
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest

private val logTag = Logger.getLogTag(OpenID4VP::class.simpleName!!)

class OpenID4VP(private val traceabilityId: String) {
    lateinit var authorizationRequest: AuthorizationRequest
    private var authorizationResponseHandler: AuthorizationResponseHandler =
        AuthorizationResponseHandler()
    private var responseUri: String? = null

    private fun setResponseUri(responseUri: String) {
        this.responseUri = responseUri
    }

    @JvmOverloads
    fun authenticateVerifier(
        urlEncodedAuthorizationRequest: String,
        trustedVerifiers: List<Verifier>,
        shouldValidateClient: Boolean = false,
    ): AuthorizationRequest {
        try {
            Logger.setTraceabilityId(traceabilityId)
            authorizationRequest = AuthorizationRequest.validateAndCreateAuthorizationRequest(
                urlEncodedAuthorizationRequest,
                trustedVerifiers,
                ::setResponseUri,
                shouldValidateClient
            )
            return this.authorizationRequest
        } catch (exception: Exception) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    fun constructVerifiablePresentationToken(verifiableCredentials: Map<String, Map<FormatType, List<String>>>): VPTokensForSigning {
        try {
            val vpTokensForSigning: Map<FormatType, VPTokenForSigning> =
                authorizationResponseHandler.constructVPTokenForSigning(
                    credentialsMap = verifiableCredentials,
                    holder = ""
                )

            return vpTokensForSigning
        } catch (exception: Exception) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    fun shareVerifiablePresentation(vpResponsesMetadata: VPResponsesMetadata): String {
        try {
            return this.authorizationResponseHandler.shareVP(
                authorizationRequest = this.authorizationRequest,
                vpResponsesMetadata = vpResponsesMetadata,
                responseUri = this.responseUri!!
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
                    url = it, method = HttpMethod.POST, mapOf("error" to exception.message!!)
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