package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.validateKey
import io.mosip.openID4VP.authorizationRequest.validateMatchOfAuthRequestObjectAndParams
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.decodeBase64ToJSON
import io.mosip.openID4VP.common.determineHttpMethod
import io.mosip.openID4VP.common.isJWT
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.isValidUrl
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest

private val className = RedirectUriSchemeAuthorizationRequestHandler::class.simpleName!!

class RedirectUriSchemeAuthorizationRequestHandler(
    authorizationRequestParameters: MutableMap<String, Any>,
    setResponseUri: (String) -> Unit
) : ClientIdSchemeBasedAuthorizationRequestHandler(authorizationRequestParameters, setResponseUri) {

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

}