package io.mosip.openID4VP.responseModeHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationResponse.AuthorizationResponse
import io.mosip.openID4VP.authorizationResponse.toJsonEncodedMap
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.jwt.jwe.JWEHandler
import io.mosip.openID4VP.constants.ContentType
import io.mosip.openID4VP.constants.HttpMethod
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
        authorizationRequest: AuthorizationRequest,
        url: String,
        authorizationResponse: AuthorizationResponse
    ): String {
        val bodyParams = authorizationResponse.toJsonEncodedMap()
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
            method = HttpMethod.POST,
            bodyParams = encryptedBodyParams,
            headers = mapOf("Content-Type" to ContentType.APPLICATION_FORM_URL_ENCODED.value)
        )
        return response["body"].toString()
    }


}