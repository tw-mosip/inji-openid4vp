package io.mosip.openID4VP.authorizationRequest.authRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.validateMatchOfAuthRequestObjectAndParams
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.decodeBase64ToJSON
import io.mosip.openID4VP.common.determineHttpMethod
import io.mosip.openID4VP.common.isJWT
import io.mosip.openID4VP.authorizationRequest.authRequestHandler.ClientIdSchemeBasedAuthRequestHandler
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest

private val className = PreRegisteredAuthRequestHandler::class.simpleName!!

class PreRegisteredAuthRequestHandler(
    private val trustedVerifiers: List<Verifier>,
    authRequestParam: MutableMap<String, Any>,
    private val shouldValidateClient: Boolean,
    setResponseUri: (String) -> Unit
) : ClientIdSchemeBasedAuthRequestHandler(authRequestParam, setResponseUri) {
    override fun validateClientId() {
        super.validateClientId()
        if (!shouldValidateClient) return
        when {
            trustedVerifiers.isEmpty() -> throw Logger.handleException(
                exceptionType = "EmptyVerifierList",
                className = AuthorizationRequest.toString()
            )

            trustedVerifiers.none {
                it.clientId == getStringValue(authRequestParam, CLIENT_ID.value)!!
            } -> throw Logger.handleException(
                exceptionType = "InvalidVerifierClientID",
                className = className
            )
        }
    }

    override fun gatherAuthRequest() {
        authRequestParam = authRequestParam[REQUEST_URI.value]?.let {
            val requestUri = getStringValue(authRequestParam, REQUEST_URI.value)!!
            val requestUriMethod = getStringValue(authRequestParam, REQUEST_URI_MODE.value) ?: "get"
            val httpMethod = determineHttpMethod(requestUriMethod)
            val response = sendHTTPRequest(requestUri, httpMethod)
            if (isJWT(response)) {
                throw Logger.handleException(
                    exceptionType = "InvalidData",
                    className = className,
                    message = "Authorization Request must not be signed for given client_id_scheme"
                )
            } else {
                val authorizationRequestObject = decodeBase64ToJSON(response)
                validateMatchOfAuthRequestObjectAndParams(authRequestParam, authorizationRequestObject)
                authorizationRequestObject
            }
        } ?: authRequestParam
    }

    override fun validateAndParseRequestFields() {
        super.validateAndParseRequestFields()

        if (!shouldValidateClient) return
        when {
            trustedVerifiers.isEmpty() -> throw Logger.handleException(
                exceptionType = "EmptyVerifierList",
                className = AuthorizationRequest.toString()
            )

            trustedVerifiers.none {
                it.clientId == getStringValue(authRequestParam, CLIENT_ID.value)!!
                        &&  it.responseUris.contains(getStringValue(authRequestParam, RESPONSE_URI.value)!!)
            } -> throw Logger.handleException(
                exceptionType = "InvalidVerifierClientID",
                className = className
            )
        }

    }
}