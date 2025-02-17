package io.mosip.openID4VP.authorizationRequest.authRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.REQUEST_URI
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.REQUEST_URI_MODE
import io.mosip.openID4VP.authorizationRequest.authRequestHandler.ClientIdSchemeBasedAuthRequestHandler
import io.mosip.openID4VP.authorizationRequest.validateMatchOfAuthRequestObjectAndParams
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.determineHttpMethod
import io.mosip.openID4VP.common.extractDataJsonFromJwt
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.isJWT
import io.mosip.openID4VP.jwt.JwtHandler
import io.mosip.openID4VP.jwt.keyResolver.types.DidKeyResolver
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest

private val className = DidAuthRequestHandler::class.simpleName!!

class DidAuthRequestHandler(
    authRequestParam: MutableMap<String, Any>,
    setResponseUri: (String) -> Unit
) : ClientIdSchemeBasedAuthRequestHandler(authRequestParam, setResponseUri) {
    override fun gatherAuthRequest() {
        authRequestParam[REQUEST_URI.value]?.let {
            val requestUri = getStringValue(authRequestParam, REQUEST_URI.value)!!
            val requestUriMethod = getStringValue(authRequestParam, REQUEST_URI_MODE.value) ?: "get"
            val httpMethod = determineHttpMethod(requestUriMethod)
            val response = sendHTTPRequest(requestUri, httpMethod)
            val authorizationRequestObject: MutableMap<String, Any>

            if (isJWT(response)) {
                JwtHandler(response, DidKeyResolver(getStringValue(authRequestParam, CLIENT_ID.value)!!)).verify()
                authorizationRequestObject = extractDataJsonFromJwt(response,
                    JwtHandler.JwtPart.PAYLOAD
                )
                validateMatchOfAuthRequestObjectAndParams(
                    authRequestParam,
                    authorizationRequestObject
                )
                authRequestParam = authorizationRequestObject
            } else throw IllegalArgumentException("Authorization Request must be signed and contain JWT for given client_id_scheme")

        } ?: throw Logger.handleException(
            exceptionType = "MissingInput",
            className = className,
            message = "request_uri must be present for given client_id_scheme"
        )
    }
}

