package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.validateMatchOfAuthRequestObjectAndParams
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.decodeBase64ToJSON
import io.mosip.openID4VP.common.determineHttpMethod
import io.mosip.openID4VP.common.isJWT
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.isValidUrl
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest

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
        when {
            trustedVerifiers.isEmpty() -> throw Logger.handleException(
                exceptionType = "EmptyVerifierList",
                className = AuthorizationRequest.toString()
            )

            trustedVerifiers.none {
                it.clientId == getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!
            } -> throw Logger.handleException(
                exceptionType = "InvalidVerifier",
                className = className
            )
        }
    }

    override fun fetchAuthorizationRequest() {
        authorizationRequestParameters = getStringValue(authorizationRequestParameters, REQUEST_URI.value)?.let {
            if (!isValidUrl(it))
                throw Logger.handleException(
                    exceptionType = "InvalidData",
                    className = className,
                    message = "$REQUEST_URI data is not valid"
                )
            val requestUriMethod = getStringValue(authorizationRequestParameters, REQUEST_URI_METHOD.value) ?: "get"
            val httpMethod = determineHttpMethod(requestUriMethod)
            val response = sendHTTPRequest(it, httpMethod)
            if (isJWT(response)) {
                throw Logger.handleException(
                    exceptionType = "InvalidData",
                    className = className,
                    message = "Authorization Request must not be signed for given client_id_scheme"
                )
            } else {
                val authorizationRequestObject = decodeBase64ToJSON(response)
                validateMatchOfAuthRequestObjectAndParams(authorizationRequestParameters, authorizationRequestObject)
                authorizationRequestObject
            }
        } ?: authorizationRequestParameters
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
                it.clientId == getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!
                        &&  it.responseUris.contains(getStringValue(authorizationRequestParameters, RESPONSE_URI.value)!!)
            } -> throw Logger.handleException(
                exceptionType = "InvalidVerifier",
                className = className
            )
        }

    }
}