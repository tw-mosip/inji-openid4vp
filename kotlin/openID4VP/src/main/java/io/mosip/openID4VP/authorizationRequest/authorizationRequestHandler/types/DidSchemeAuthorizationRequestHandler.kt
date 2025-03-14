package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.validateAuthorizationRequestObjectAndParameters
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.extractDataJsonFromJws
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.isJWS
import io.mosip.openID4VP.jwt.jws.JWSHandler
import io.mosip.openID4VP.jwt.jws.JWSHandler.JwsPart.PAYLOAD
import io.mosip.openID4VP.jwt.keyResolver.types.DidPublicKeyResolver
import io.mosip.openID4VP.networkManager.CONTENT_TYPE.APPLICATION_JWT
import okhttp3.Headers

private val className = DidSchemeAuthorizationRequestHandler::class.simpleName!!

class DidSchemeAuthorizationRequestHandler(
    authorizationRequestParameters: MutableMap<String, Any>,
    setResponseUri: (String) -> Unit
) : ClientIdSchemeBasedAuthorizationRequestHandler(authorizationRequestParameters, setResponseUri) {
    override fun validateRequestUriResponse() {
        if(requestUriResponse.isNotEmpty()){
            val headers = requestUriResponse["header"] as Headers
            val responseBody = requestUriResponse["body"].toString()

            if(isValidContentType(headers) &&  isJWS(responseBody)){
                val didUrl = getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!
                JWSHandler(
                    responseBody,
                    DidPublicKeyResolver(didUrl)
                ).verify()
                val authorizationRequestObject = extractDataJsonFromJws(
                    responseBody,
                    PAYLOAD
                )

                validateAuthorizationRequestObjectAndParameters(
                    authorizationRequestParameters,
                    authorizationRequestObject
                )
                authorizationRequestParameters = authorizationRequestObject

            } else
                throw Logger.handleException(
                    exceptionType = "InvalidData",
                    className = className,
                    message = "Authorization Request must be signed for given client_id_scheme"
                )

        } else  throw Logger.handleException(
            exceptionType = "MissingInput",
            className = className,
            fieldPath = listOf(REQUEST_URI.value),
        )
    }

    private fun isValidContentType(headers: Headers): Boolean =
        headers["content-type"]?.contains(APPLICATION_JWT.value, ignoreCase = true) == true
}

