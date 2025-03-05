package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.validateAttribute
import io.mosip.openID4VP.authorizationRequest.validateAuthorizationRequestObjectAndParameters
import io.mosip.openID4VP.networkManager.CONTENT_TYPE.APPLICATION_JSON
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

    override fun validateAndParseRequestFields(){
        super.validateAndParseRequestFields()
        val responseMode = getStringValue(authorizationRequestParameters, RESPONSE_MODE.value) ?:
        throw Logger.handleException(
            exceptionType = "MissingInput",
            className = className,
            fieldPath = listOf(RESPONSE_MODE.value)
        )
         when (responseMode) {
            "direct_post", "direct_post.jwt" -> {
                validateUriCombinations(
                    authorizationRequestParameters,
                    RESPONSE_URI.value,
                    REDIRECT_URI.value
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
        authRequestParam: Map<String, Any>,
        validAttribute: String,
        inValidAttribute: String,
    )  {
        when {
            authRequestParam.containsKey(inValidAttribute) -> {
                throw Logger.handleException(
                    exceptionType = "InvalidData",
                    className = className,
                    message = "$inValidAttribute should not be present for given response_mode"
                )
            }
            else -> {
                validateAttribute(authRequestParam, validAttribute)
            }
        }
        if(authRequestParam[validAttribute] != authRequestParam[CLIENT_ID.value])
            throw Logger.handleException(
                exceptionType = "InvalidVerifierRedirectUri",
                className = className,
                message = "$validAttribute should be equal to client_id for given client_id_scheme"
            )

    }

    private fun isValidContentType(headers: Headers): Boolean =
        headers["content-type"]?.contains(APPLICATION_JSON.value, ignoreCase = true) == true

}