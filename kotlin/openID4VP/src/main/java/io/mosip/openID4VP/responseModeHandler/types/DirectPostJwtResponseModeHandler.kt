package io.mosip.openID4VP.responseModeHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.VPToken
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.encodeToJsonString
import io.mosip.openID4VP.jwt.jwe.JWEHandler
import io.mosip.openID4VP.networkManager.CONTENT_TYPE
import io.mosip.openID4VP.networkManager.HTTP_METHOD
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
        vpToken: VPToken,
        authorizationRequest: AuthorizationRequest,
        presentationSubmission: PresentationSubmission,
        state: String?,
        url: String
    ): String {
        val encodedVPToken = encodeToJsonString(vpToken, "vp_token", className)
        val encodedPresentationSubmission =
            encodeToJsonString(presentationSubmission, "presentation_submission", className)
        val bodyParams = mapOf(
            "vp_token" to encodedVPToken,
            "presentation_submission" to encodedPresentationSubmission,
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