package io.mosip.openID4VP

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponseHandler
import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.CredentialFormatSpecificSigningData
import io.mosip.openID4VP.common.FormatType
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.encodeVPTokenForSigning
import io.mosip.openID4VP.dto.VPResponseMetadata.VPResponseMetadata
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest

private val logTag = Logger.getLogTag(OpenID4VP::class.simpleName!!)
class OpenID4VP(private val traceabilityId: String) {
    private lateinit var credentialsMap: Map<String, Map<String, List<Any>>>
    lateinit var authorizationRequest: AuthorizationRequest
    private var responseUri: String? = null
    private lateinit var authorizationResponseHandler: AuthorizationResponseHandler
    private lateinit var vpTokensForSigning: Map<FormatType, CredentialFormatSpecificSigningData>

    private fun setResponseUri(responseUri: String) {
        this.responseUri = responseUri
    }

    @JvmOverloads
    fun authenticateVerifier(
        encodedAuthorizationRequest: String,
        trustedVerifiers: List<Verifier>,
        shouldValidateClient: Boolean = false
    ): AuthorizationRequest {
        try {
            Logger.setTraceabilityId(traceabilityId)
            authorizationRequest = AuthorizationRequest.validateAndGetAuthorizationRequest(
                encodedAuthorizationRequest, ::setResponseUri, trustedVerifiers, shouldValidateClient
            )
            return this.authorizationRequest
        } catch (exception: Exception) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    fun constructVerifiablePresentationToken(verifiableCredentials: Map<String, Map<String,List<Any>>>): Map<String, String> {
        try {
            val dataForSigning: Map<FormatType, CredentialFormatSpecificSigningData> =
                AuthorizationResponseHandler().constructDataForSigning(verifiableCredentials)
            this.vpTokensForSigning = dataForSigning
            this.credentialsMap = verifiableCredentials
            return encodeVPTokenForSigning(dataForSigning)
        } catch (exception: Exception) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    fun shareVerifiablePresentation(vpResponseMetadata: Map<String,VPResponseMetadata>): String {
        try {
            val formattedVPResponseMetadata: MutableMap<FormatType, VPResponseMetadata> = mutableMapOf()

            for ((key, value) in vpResponseMetadata) {
                val enumKey = FormatType.entries.find { it.value == key }
                if (enumKey != null) {
                    formattedVPResponseMetadata[enumKey] = value
                }
            }

            authorizationResponseHandler = AuthorizationResponseHandler()
            val authorizationResponse = this.authorizationResponseHandler.createAuthorizationResponse(
                authorizationRequest = this.authorizationRequest,
                signingDataForAuthorizationResponseCreation = formattedVPResponseMetadata,
                vpTokensForSigning = this.vpTokensForSigning,
                credentialsMap = this.credentialsMap
            )
            return this.authorizationResponseHandler.sendAuthorizationResponseToVerifier(
                authorizationResponse = authorizationResponse,
                authorizationRequest = this.authorizationRequest
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