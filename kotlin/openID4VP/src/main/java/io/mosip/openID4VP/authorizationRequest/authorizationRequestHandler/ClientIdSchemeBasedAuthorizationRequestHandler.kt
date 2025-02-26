package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.ClientIdScheme.PRE_REGISTERED
import io.mosip.openID4VP.authorizationRequest.parseAndValidateClientMetadata
import io.mosip.openID4VP.authorizationRequest.parseAndValidatePresentationDefinition
import io.mosip.openID4VP.authorizationRequest.validateAttribute
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.determineHttpMethod
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.isValidUrl
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest

private val className = ClientIdSchemeBasedAuthorizationRequestHandler::class.simpleName!!

abstract class ClientIdSchemeBasedAuthorizationRequestHandler(
    var authorizationRequestParameters: MutableMap<String, Any>,
    val setResponseUri: (String) -> Unit
) {
    var requestUriResponse: Map<String, Any> = emptyMap()

    open fun validateClientId() {
        validateAttribute(authorizationRequestParameters, CLIENT_ID.value)
    }

    fun fetchAuthorizationRequest() {
        getStringValue(authorizationRequestParameters, REQUEST_URI.value)?.let {
            if (!isValidUrl(it))
                throw Logger.handleException(
                    exceptionType = "InvalidData",
                    className = className,
                    message = "${REQUEST_URI.value} data is not valid"
                )
            val requestUriMethod =
                getStringValue(authorizationRequestParameters, REQUEST_URI_METHOD.value) ?: "get"
            val httpMethod = determineHttpMethod(requestUriMethod)
            requestUriResponse =  sendHTTPRequest(it, httpMethod)
        }
        this.validateRequestUriResponse()
    }

    abstract fun validateRequestUriResponse()

    fun setResponseUrl() {
        val responseMode = getStringValue(authorizationRequestParameters, RESPONSE_MODE.value) ?:
            throw Logger.handleException(
                exceptionType = "MissingInput",
                className = className,
                fieldPath = listOf(RESPONSE_MODE.value)
            )
        val verifierResponseUri = when (responseMode) {
            "direct_post" -> {
                validateAttribute(authorizationRequestParameters, RESPONSE_URI.value)
                getStringValue(authorizationRequestParameters, RESPONSE_URI.value)
            }

            else -> throw Logger.handleException(
                exceptionType = "InvalidResponseMode",
                className = className,
                message = "Given response_mode is not supported"
            )
        }
        if (!isValidUrl(verifierResponseUri!!)) {
            throw Logger.handleException(
                exceptionType = "InvalidData",
                className = className,
                message = "${RESPONSE_URI.value} data is not valid"
            )
        }
        setResponseUri(verifierResponseUri)

    }

    open fun validateAndParseRequestFields() {
        validateAttribute(authorizationRequestParameters, RESPONSE_TYPE.value)
        validateAttribute(authorizationRequestParameters, NONCE.value)
        getStringValue(authorizationRequestParameters, STATE.value)?.let {
            validateAttribute(
                authorizationRequestParameters,
                STATE.value
            )
        }
        parseAndValidateClientMetadata(authorizationRequestParameters)
        parseAndValidatePresentationDefinition(authorizationRequestParameters)
    }

    fun createAuthorizationRequest(
    ): AuthorizationRequest {
        return AuthorizationRequest(
            clientId = getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!,
            clientIdScheme = getStringValue(authorizationRequestParameters, CLIENT_ID_SCHEME.value) ?: PRE_REGISTERED.value,
            responseType = getStringValue(authorizationRequestParameters, RESPONSE_TYPE.value)!!,
            responseMode = getStringValue(authorizationRequestParameters, RESPONSE_MODE.value),
            presentationDefinition = authorizationRequestParameters[PRESENTATION_DEFINITION.value]!!,
            responseUri = getStringValue(authorizationRequestParameters, RESPONSE_URI.value),
            redirectUri = getStringValue(authorizationRequestParameters, REDIRECT_URI.value),
            nonce = getStringValue(authorizationRequestParameters, NONCE.value)!!,
            state = getStringValue(authorizationRequestParameters, STATE.value),
            clientMetadata = getStringValue(authorizationRequestParameters, CLIENT_METADATA.value),
        )
    }
}
