package io.mosip.openID4VP.responseModeHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
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
    override fun validate(
        clientMetadata: ClientMetadata?,
        walletMetadata: WalletMetadata?,
        shouldValidateWithWalletMetadata: Boolean
    ) {
        if (clientMetadata == null) {
            throw Logger.handleException(
                exceptionType = "InvalidData",
                message = "client_metadata must be present for given response mode",
                className = className
            )
        }
        val alg = clientMetadata.authorizationEncryptedResponseAlg ?: throwMissingInputException(
            "authorization_encrypted_response_alg"
        )
        val enc = clientMetadata.authorizationEncryptedResponseEnc ?: throwMissingInputException(
            "authorization_encrypted_response_enc"
        )
        val jwks = clientMetadata.jwks ?: throwMissingInputException("jwks")

        if (jwks.keys.none { it.alg == alg }) {
            throwInvalidDataException("No jwk matching the specified algorithm found")
        }

        if (shouldValidateWithWalletMetadata) {
            if (walletMetadata == null) {
                throwInvalidDataException("wallet_metadata must be present")
            }
            walletMetadata.authorizationEncryptionEncValuesSupported?.let { encSupported ->
                if (!encSupported.contains(enc)) {
                    throwInvalidDataException("authorization_encrypted_response_enc is not supported")
                }
            }?: throwInvalidDataException("authorization_encryption_enc_values_supported must be present in wallet_metadata")

            walletMetadata.authorizationEncryptionAlgValuesSupported?.let { algSupported ->
                if (!algSupported.contains(alg)) {
                    throwInvalidDataException("authorization_encrypted_response_alg is not supported")
                }
            } ?: throwInvalidDataException("authorization_encryption_alg_values_supported must be present in wallet_metadata")
        }
    }

    private fun throwMissingInputException(fieldName: String): Nothing {
        throw Logger.handleException(
            exceptionType = "MissingInput",
            className = className,
            fieldPath = listOf("client_metadata", fieldName)
        )
    }

    private fun throwInvalidDataException(message: String): Nothing {
        throw Logger.handleException(
            exceptionType = "InvalidData",
            className = className,
            message = message
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