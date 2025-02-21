package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.validateKey
import io.mosip.openID4VP.authorizationRequest.validateMatchOfAuthRequestObjectAndParams
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.convertJsonToMap
import io.mosip.openID4VP.common.getStringValue
import okhttp3.Headers

private val className = RedirectUriSchemeAuthorizationRequestHandler::class.simpleName!!

class RedirectUriSchemeAuthorizationRequestHandler(
    authorizationRequestParameters: MutableMap<String, Any>,
    setResponseUri: (String) -> Unit
) : ClientIdSchemeBasedAuthorizationRequestHandler(authorizationRequestParameters, setResponseUri) {

    override fun validateRequestUriResponse() {
        authorizationRequestParameters = if (requestUriResponse.isEmpty())
            authorizationRequestParameters
        else {
            val headers = requestUriResponse["header"] as Headers
            val responseBody = requestUriResponse["body"].toString()

            if (isValidContentType(headers)) {
                val authorizationRequestObject = convertJsonToMap(responseBody)
                validateMatchOfAuthRequestObjectAndParams(
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

    override fun validateAndParseRequestFields(){
        super.validateAndParseRequestFields()
        val responseMode = getStringValue(authorizationRequestParameters, RESPONSE_MODE.value) ?: "fragment"
         when (responseMode) {
            "direct_post", "direct_post.jwt" -> {
                validateUriCombinations(authorizationRequestParameters,
                    RESPONSE_URI.value,
                    REDIRECT_URI.value
                )
            }
            "fragment" -> {
                validateUriCombinations(authorizationRequestParameters,
                    REDIRECT_URI.value,
                    RESPONSE_URI.value,
                )
            }
            else -> throw Logger.handleException(
                exceptionType = "InvalidResponseMode",
                className = className,
                message = "Given response_mode is not supported"
            )
        }
    }

    private fun validateUriCombinations(
        authRequestParam: MutableMap<String, Any>,
        validKey: String,
        inValidKey: String,
    )  {
        when {
            authRequestParam.containsKey(inValidKey) -> {
                throw Logger.handleException(
                    exceptionType = "InvalidInput",
                    className = className,
                    message = "$inValidKey should not be present for given response_mode"
                )
            }
            else -> {
                validateKey(authRequestParam, validKey)
            }
        }
        if(authRequestParam[validKey] != authRequestParam[CLIENT_ID.value]!!)
            throw Logger.handleException(
                exceptionType = "InvalidVerifierRedirectUri",
                className = className,
                message = "$validKey should be equal to client_id for given client_id_scheme"
            )

    }

    private fun isValidContentType(headers: Headers): Boolean =
        headers["content-type"]?.contains("application/json", ignoreCase = true) == true

}