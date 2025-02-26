package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.validateAuthorizationRequestObjectAndParameters
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.convertJsonToMap
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.networkManager.CONTENT_TYPES.APPLICATION_JSON
import okhttp3.Headers

private val className = PreRegisteredSchemeAuthorizationRequestHandler::class.simpleName!!

class PreRegisteredSchemeAuthorizationRequestHandler(
    private val trustedVerifiers: List<Verifier>,
    authorizationRequestParameters: MutableMap<String, Any>,
    private val shouldValidateClient: Boolean,
    setResponseUri: (String) -> Unit
) : ClientIdSchemeBasedAuthorizationRequestHandler(authorizationRequestParameters, setResponseUri) {
    override fun validateClientId() {
        super.validateClientId()
        if (!shouldValidateClient) return

        val clientId = getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!

        if (trustedVerifiers.none { it.clientId == clientId }) {
            throw Logger.handleException(
                exceptionType = "InvalidVerifier",
                className = className,
                message = "Verifier is not trusted by the wallet"
            )
        }
    }

    override fun validateRequestUriResponse() {

        authorizationRequestParameters = if (requestUriResponse.isEmpty())
            authorizationRequestParameters
        else {
            val headers = requestUriResponse["header"] as Headers
            val responseBody = requestUriResponse["body"].toString()

            if (isValidContentType(headers)) {
                val authorizationRequestObject = convertJsonToMap(responseBody)
                validateAuthorizationRequestObjectAndParameters(
                    authorizationRequestParameters,
                    authorizationRequestObject
                )
                authorizationRequestObject
            } else {
                throw Logger.handleException(
                    exceptionType = "InvalidData",
                    className = className,
                    message = "Authorization Request must not be signed for given client_id_scheme"
                )
            }
        }
    }

    override fun validateAndParseRequestFields() {
        super.validateAndParseRequestFields()

        if (!shouldValidateClient) return

        val clientId = getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!
        val responseUri = getStringValue(authorizationRequestParameters, RESPONSE_URI.value)!!

        if (trustedVerifiers.none { it.clientId == clientId && it.responseUris.contains(responseUri) }) {
            throw Logger.handleException(
                exceptionType = "InvalidVerifier",
                className = className,
                message = "Verifier is not trusted by the wallet"
            )
        }

    }

    private fun isValidContentType(headers: Headers): Boolean =
        headers["content-type"]?.contains(APPLICATION_JSON.value, ignoreCase = true) == true
}