package io.mosip.openID4VP

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponseHandler
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.Verifier
import io.mosip.openID4VP.constants.VCFormatType
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.VPResponseMetadata
import io.mosip.openID4VP.constants.ContentType
import io.mosip.openID4VP.common.generateNonce
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.common.OpenID4VPErrorFields.STATE
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import java.util.logging.Level
import java.util.logging.Logger

class OpenID4VP(
    private val traceabilityId: String,
    private val vpSigningAlgorithmSupported: Map<FormatType, List<String>>? = null,
    //private val walletMetadata: WalletMetadata? = null
) {
    lateinit var authorizationRequest: AuthorizationRequest
    private var authorizationResponseHandler: AuthorizationResponseHandler =
        AuthorizationResponseHandler()
    private var responseUri: String? = null
    private var walletMetadata =
        vpSigningAlgorithmSupported?.let { WalletMetadata.construct(vpSigningAlgorithmSupported) }
    private lateinit var walletNonce: String

    private fun setResponseUri(responseUri: String) {
        this.responseUri = responseUri
    }

    private fun logTag(): String =
        "INJI-OpenID4VP : class name - ${OpenID4VP::class.simpleName} | traceID - $traceabilityId"

    @JvmOverloads
    fun authenticateVerifier(
        urlEncodedAuthorizationRequest: String,
        trustedVerifiers: List<Verifier>,
        shouldValidateClient: Boolean = true,
    ): AuthorizationRequest {
        try {
            walletNonce = generateNonce()
            authorizationRequest = AuthorizationRequest.validateAndCreateAuthorizationRequest(
                urlEncodedAuthorizationRequest,
                trustedVerifiers,
                walletMetadata,
                ::setResponseUri,
                shouldValidateClient,
                walletNonce
            )
            return this.authorizationRequest
        } catch (exception: OpenID4VPExceptions) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    fun constructUnsignedVPToken(
        verifiableCredentials: Map<String, Map<VCFormatType, List<Any>>>,
        holderId: String? = null,
        signatureSuite: String? = null
    ): Map<VCFormatType, UnsignedVPToken> {
        try {
            return authorizationResponseHandler.constructUnsignedVPToken(
                credentialsMap = verifiableCredentials,
                authorizationRequest = this.authorizationRequest,
                responseUri = this.responseUri!!,
                holderId = holderId,
                signatureSuite = signatureSuite,
                nonce = walletNonce
            )
        } catch (exception: OpenID4VPExceptions) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    fun shareVerifiablePresentation(vpTokenSigningResults: Map<VCFormatType, VPTokenSigningResult>): String {
        try {
            return this.authorizationResponseHandler.shareVP(
                authorizationRequest = this.authorizationRequest,
                vpTokenSigningResults = vpTokenSigningResults,
                responseUri = this.responseUri!!
            )
        } catch (exception: OpenID4VPExceptions) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    fun sendErrorToVerifier(exception: Exception) {
        responseUri?.let { uri ->
            try {
                val errorPayload: MutableMap<String, String> = when (exception) {
                    is OpenID4VPExceptions -> exception.toErrorResponse()
                    else -> OpenID4VPExceptions.GenericFailure(
                        message = exception.message ?: "Unknown internal error",
                        className = "OpenID4VP.kt"
                    ).toErrorResponse()
                }
                this.authorizationRequest.state?.takeIf { it.isNotBlank() }?.let {
                    errorPayload[STATE] = it
                }

                sendHTTPRequest(
                    url = uri,
                    method = HttpMethod.POST,
                    bodyParams = errorPayload,
                    headers = mapOf("Content-Type" to ContentType.APPLICATION_FORM_URL_ENCODED.value)
                )
            } catch (e: Exception) {
                Logger.getLogger(logTag()).log(Level.SEVERE, "Failed to send error to verifier: ${e.message}")
            }
        }
    }


    @Deprecated("This method supports constructing VP token for LDP VC without canonicalization of the data sent for signing")
    fun constructVerifiablePresentationToken(verifiableCredentials: Map<String, List<String>>): String {
        try {
            return authorizationResponseHandler.constructUnsignedVPTokenV1(
                verifiableCredentials = verifiableCredentials,
                authorizationRequest = this.authorizationRequest,
                responseUri = this.responseUri!!
            )
        } catch (exception: Exception) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }

    @Deprecated("This method only supports sharing LDP VC in direct post response mode")
    fun shareVerifiablePresentation(vpResponseMetadata: VPResponseMetadata): String {
        try {
            return authorizationResponseHandler.shareVPV1(
                vpResponseMetadata = vpResponseMetadata,
                authorizationRequest = this.authorizationRequest,
                responseUri = this.responseUri!!
            )
        } catch (exception: Exception) {
            sendErrorToVerifier(exception)
            throw exception
        }
    }


}
