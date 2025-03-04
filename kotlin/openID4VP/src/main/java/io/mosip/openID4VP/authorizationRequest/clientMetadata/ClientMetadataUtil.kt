package io.mosip.openID4VP.authorizationRequest.clientMetadata

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_METADATA
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_MODE
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.ResponseMode.DIRECT_POST_JWT

private val className = ClientMetadata::class.simpleName!!
fun parseAndValidateClientMetadata(authorizationRequestParameters: MutableMap<String, Any>) {
    authorizationRequestParameters[CLIENT_METADATA.value]?.let {
        val clientMetadata = when (it) {
            is String -> deserializeAndValidate(it, ClientMetadataSerializer)
            is Map<*, *> -> deserializeAndValidate(it as Map<String, Any>, ClientMetadataSerializer)
            else -> throw Logger.handleException(
                exceptionType = "InvalidData",
                message = "client_metadata must be of type String or Map ",
                className = className
            )
        }
        validateClientMetadataBasedOnResponseMode(clientMetadata, authorizationRequestParameters)
        authorizationRequestParameters[CLIENT_METADATA.value] = clientMetadata
    }
}

//TODO: revisit the exception names and fields
private fun validateClientMetadataBasedOnResponseMode(
    clientMetadata: ClientMetadata,
    authorizationRequestParameters: MutableMap<String, Any>
) {

    val responseMode = authorizationRequestParameters[RESPONSE_MODE.value] ?: return

    if (responseMode == DIRECT_POST_JWT.value) {
        // Check for required encryption parameters
        val alg = clientMetadata.authorizationEncryptedResponseAlg
            ?: throw Logger.handleException(
                exceptionType = "MissingEncryptionParameters", // TODO:
                message = "Missing required encryption algorithm",
                className = className
            )

        clientMetadata.authorizationEncryptedResponseEnc
            ?: throw Logger.handleException(
                exceptionType = "MissingEncryptionParameters", //TODO:
                message = "Missing required encryption encoding",
                className = className
            )

        // Check for matching JWK
        val jwks = clientMetadata.jwks ?: throw Logger.handleException(
            exceptionType = "MissingEncryptionKey", //TODO:
            message = "No JWKs found in client_metadata",
            fieldPath = listOf("jwks"),
            className = className
        )

        if (jwks.keys.none { it.alg == alg }) {
            throw Logger.handleException(
                exceptionType = "MissingEncryptionKey",
                message = "No JWK matching the specified algorithm found: $alg",
                fieldPath = listOf("jwks", "keys"),
                className = className
            )
        }
    }
}