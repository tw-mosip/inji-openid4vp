package io.mosip.openID4VP

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponseHandler
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.authorizationRequest.Verifier
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponseHandlerV1
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.VPResponseMetadata
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest

private val logTag = Logger.getLogTag(OpenID4VP::class.simpleName!!)

class OpenID4VP(private val traceabilityId: String) {
    lateinit var authorizationRequest: AuthorizationRequest
    private var authorizationResponseHandler: AuthorizationResponseHandler =
        AuthorizationResponseHandler()
    private var authorizationResponseHandlerV1: AuthorizationResponseHandlerV1 =
        AuthorizationResponseHandlerV1()
    private var responseUri: String? = null

    private fun setResponseUri(responseUri: String) {
        this.responseUri = responseUri
    }

    fun authenticateVerifier(
        urlEncodedAuthorizationRequest: String,
        trustedVerifiers: List<Verifier>,
        walletMetadata: WalletMetadata? = null,
        shouldValidateClient: Boolean = false
    ): AuthorizationRequest {
        try {
            Logger.setTraceabilityId(traceabilityId)
            authorizationRequest = AuthorizationRequest.validateAndCreateAuthorizationRequest(
                urlEncodedAuthorizationRequest, trustedVerifiers, walletMetadata, ::setResponseUri,shouldValidateClient
            )
            return this.authorizationRequest
        } catch (exception: Exception) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    @Deprecated("Use the version with WalletMetadata parameter instead")
    fun authenticateVerifier(
        urlEncodedAuthorizationRequest: String,
        trustedVerifiers: List<Verifier>,
        shouldValidateClient: Boolean = false
    ): AuthorizationRequest {
        try {
            Logger.setTraceabilityId(traceabilityId)
            authorizationRequest = AuthorizationRequest.validateAndCreateAuthorizationRequest(
                urlEncodedAuthorizationRequest, trustedVerifiers,null, ::setResponseUri,shouldValidateClient
            )
            return this.authorizationRequest
        } catch (exception: Exception) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    fun constructUnsignedVPToken(verifiableCredentials: Map<String, Map<FormatType, List<Any>>>, holderId: String): Map<FormatType, UnsignedVPToken> {
        try {
            return authorizationResponseHandler.constructUnsignedVPToken(
                credentialsMap = verifiableCredentials,
                authorizationRequest = this.authorizationRequest,
                responseUri = this.responseUri!!,
                holderId = holderId
            )
        } catch (exception: Exception) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    @Deprecated("Use constructUnsignedVPToken with Map<String, Map<FormatType, List<Any>>> instead")
    fun constructVerifiablePresentationToken(verifiableCredentials: Map<String, List<String>>): String {
        try {
            return authorizationResponseHandlerV1.constructUnsignedVPToken(
                verifiableCredentials = verifiableCredentials,
                authorizationRequest = this.authorizationRequest,
                responseUri = this.responseUri!!
            )
        } catch (exception: Exception) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    fun shareVerifiablePresentation(vpTokenSigningResults: Map<FormatType, VPTokenSigningResult>): String {
        try {
            return this.authorizationResponseHandler.shareVP(
                authorizationRequest = this.authorizationRequest,
                vpTokenSigningResults = vpTokenSigningResults,
                responseUri = this.responseUri!!
            )
        } catch (exception: Exception) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    @Deprecated("Use the version with VPResponseMetadata parameter instead")
    fun shareVerifiablePresentation(vpResponseMetadata: VPResponseMetadata): String {
        try {
            return authorizationResponseHandlerV1.shareVP(
                vpResponseMetadata = vpResponseMetadata,
                authorizationRequest = this.authorizationRequest,
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
