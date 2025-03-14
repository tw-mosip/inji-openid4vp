package io.mosip.openID4VP.responseModeHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.jwt.jwe.JWEHandler
import io.mosip.openID4VP.networkManager.CONTENT_TYPE
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandler

private val className = DirectPostJwtResponseModeHandler::class.simpleName!!

class DirectPostJwtResponseModeHandler : ResponseModeBasedHandler() {
    override fun validate(clientMetadata: ClientMetadata?) {
        clientMetadata?.let {
            val alg = clientMetadata.authorizationEncryptedResponseAlg
                ?: throw Logger.handleException(
                    exceptionType = "MissingInput",
                    className = className,
                    fieldPath = listOf("client_metadata", "authorization_encrypted_response_alg")
                )
            clientMetadata.authorizationEncryptedResponseEnc
                ?: throw Logger.handleException(
                    exceptionType = "MissingInput",
                    className = className,
                    fieldPath = listOf("client_metadata", "authorization_encrypted_response_enc")
                )
            val jwks = clientMetadata.jwks
                ?: throw throw Logger.handleException(
                    exceptionType = "MissingInput",
                    className = className,
                    fieldPath = listOf("client_metadata", "jwks")
                )
            if (jwks.keys.none { it.alg == alg }) {
                throw Logger.handleException(
                    exceptionType = "InvalidData",
                    message = "No jwk matching the specified algorithm found",
                    className = className
                )
            }
        } ?: throw Logger.handleException(
            exceptionType = "InvalidData",
            message = "client_metadata must be present for given response mode",
            className = className
        )
    }

    override fun sendAuthorizationResponse(
        vpToken: VPTokenType,
        authorizationRequest: AuthorizationRequest,
        presentationSubmission: PresentationSubmission,
        state: String?,
        url: String
    ): String {
        val bodyParams = mapOf(
            "vp_token" to vpToken,
            "presentation_submission" to presentationSubmission,
        ).let { baseParams ->
            state?.let { baseParams + mapOf("state" to it) } ?: baseParams
        }
        val clientMetadata = authorizationRequest.clientMetadata!!

        val jwk =
            clientMetadata.jwks?.keys?.find { it.alg == clientMetadata.authorizationEncryptedResponseAlg }!!

        val jweHandler = JWEHandler(
            clientMetadata.authorizationEncryptedResponseAlg!!,
            clientMetadata.authorizationEncryptedResponseEnc!!,
            jwk
        )
        val encryptedBody = jweHandler.generateEncryptedResponse(bodyParams)
        val encryptedBodyParams = mapOf("response" to encryptedBody)

        val response = sendHTTPRequest(
            url = url,
            method = HTTP_METHOD.POST,
            bodyParams = encryptedBodyParams,
            headers = mapOf("Content-Type" to CONTENT_TYPE.APPLICATION_FORM_URL_ENCODED.value)
        )
        return response["body"].toString()
    }


}