package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.validateMatchOfAuthRequestObjectAndParams
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.extractDataJsonFromJwt
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.isJWT
import io.mosip.openID4VP.jwt.JwtHandler
import io.mosip.openID4VP.jwt.keyResolver.types.DidKeyResolver
import okhttp3.Headers

private val className = DidSchemeAuthorizationRequestHandler::class.simpleName!!

class DidSchemeAuthorizationRequestHandler(
    authorizationRequestParameters: MutableMap<String, Any>,
    setResponseUri: (String) -> Unit
) : ClientIdSchemeBasedAuthorizationRequestHandler(authorizationRequestParameters, setResponseUri) {
    override fun validateClientId(){
        super.validateClientId()
        if(!getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!.startsWith("did"))
            throw Logger.handleException(
                exceptionType =  "InvalidData",
                className = className,
                message = "Given client id is not valid"
            )
    }

    override fun validateRequestUriResponse() {
        if(requestUriResponse.isNotEmpty()){
            val headers = requestUriResponse["header"] as Headers
            val responseBody = requestUriResponse["body"].toString()

            if(isValidContentType(headers) &&  isJWT(responseBody)){
                JwtHandler(
                    responseBody,
                    DidKeyResolver(getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!)
                ).verify()
                val authorizationRequestObject = extractDataJsonFromJwt(
                    responseBody,
                    JwtHandler.JwtPart.PAYLOAD
                )

                validateMatchOfAuthRequestObjectAndParams(
                    authorizationRequestParameters,
                    authorizationRequestObject
                )
                authorizationRequestParameters = authorizationRequestObject

            } else
                throw Logger.handleException(
                    exceptionType = "InvalidData",
                    className = className,
                    message = "Authorization Request must not be signed for given ${CLIENT_ID_SCHEME.value}"
                )

        } else  throw Logger.handleException(
            exceptionType = "MissingInput",
            className = className,
            message = "${REQUEST_URI.value} must be present for given ${CLIENT_ID_SCHEME.value}"
        )
    }

    private fun isValidContentType(headers: Headers): Boolean =
        headers["content-type"]?.contains("application/oauth-authz-req+jwt", ignoreCase = true) == true
}

