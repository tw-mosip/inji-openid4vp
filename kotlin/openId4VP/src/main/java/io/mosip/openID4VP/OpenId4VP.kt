package io.mosip.openID4VP

import io.mosip.openID4VP.authenticationResponse.AuthenticationResponse
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponse
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.dto.VPResponseMetadata
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHttpPostRequest
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class OpenId4VP(private val traceabilityId: String) {
    lateinit var authorizationRequest: AuthorizationRequest
    lateinit var presentationDefinitionId: String
    var responseUri: String? = null
    private val logTag = Logger.getLogTag(this::class.simpleName!!)


    fun authenticateVerifier(
        encodedAuthorizationRequest: String, trustedVerifiers: List<Verifier>
    ): Map<String, String> {
        try {
            Logger.setTraceability(traceabilityId)
            this.authorizationRequest =
                AuthorizationRequest.getAuthorizationRequest(encodedAuthorizationRequest, this)

            val authenticationResponse =
                AuthenticationResponse.getAuthenticationResponse(trustedVerifiers, this)

            return authenticationResponse
        } catch (exception: Exception) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    fun constructVerifiablePresentationToken(verifiableCredentials: Map<String, List<String>>): String {
        try {
            return AuthorizationResponse.constructVPTokenForSigning(verifiableCredentials)
        }catch (exception: Exception) {
            sendErrorToVerifier(exception)
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
        CoroutineScope(Dispatchers.IO).launch {
            try {
                responseUri?.let {
                    sendHttpPostRequest(
                        it, mapOf("error" to exception.message!!)
                    )
                }
            } catch (exception: Exception) {
                println("Error: logTag: INJI-OpenID4VP : class name - Companion | traceID - test-OpenId4VP | Message: ${exception.message}")
            }
        }
    }
}