package io.mosip.openID4VP.authorizationRequest.authRequestHandler

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.parseAndValidateClientMetadataInAuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.parseAndValidatePresentationDefinitionInAuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.validateKey
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.getStringValue

private val className = AuthorizationRequest::class.simpleName!!

abstract class ClientIdSchemeBasedAuthRequestHandler(
    var authRequestParam: MutableMap<String, Any>,
    val setResponseUri: (String) -> Unit
) {

    open fun validateClientId() {
        validateKey(authRequestParam, CLIENT_ID.value)
    }

    abstract fun gatherAuthRequest()

    fun gatherInfoForSendingResponseToVerifier() {
        val responseMode = getStringValue(authRequestParam, RESPONSE_MODE.value) ?: "fragment"
        val verifierResponseUri = when (responseMode) {
            "direct_post", "direct_post.jwt" -> {
                validateKey(authRequestParam, RESPONSE_URI.value)
                getStringValue(authRequestParam, RESPONSE_URI.value)
            }
            "fragment" -> {
                validateKey(authRequestParam, REDIRECT_URI.value)
                getStringValue(authRequestParam, REDIRECT_URI.value)
                throw Logger.handleException(
                    exceptionType = "InvalidResponseMode",
                    className = className,
                    message = "Same device flow is not supported for OVP"
                )
            }
            else -> throw Logger.handleException(
                exceptionType = "InvalidResponseMode",
                className = className,
                message = "Given response_mode is not supported"
            )
        }
        setResponseUri(verifierResponseUri!!)
    }

    open fun validateAndParseRequestFields() {
        validateKey(authRequestParam, RESPONSE_TYPE.value)
        validateKey(authRequestParam, NONCE.value)
        validateKey(authRequestParam, STATE.value)
        authRequestParam = parseAndValidateClientMetadataInAuthorizationRequest(authRequestParam)
        authRequestParam = parseAndValidatePresentationDefinitionInAuthorizationRequest(authRequestParam)
    }
}
