package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.authRequestHandler.ClientIdSchemeBasedAuthRequestHandler
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.dto.Verifier

enum class ClientIdScheme(val value: String) {
    PRE_REGISTERED("pre-registered"),
    REDIRECT_URI("redirect_uri"),
    DID("did")
}

data class AuthorizationRequest(
    val clientId: String,
    val clientIdScheme: String,
    val responseType: String,
    val responseMode: String?,
    var presentationDefinition: Any,
    val responseUri: String?,
    val redirectUri: String?,
    val nonce: String,
    val state: String,
    var clientMetadata: Any? = null
) {
    init {
        require(presentationDefinition is PresentationDefinition || presentationDefinition is String) {
            "presentationDefinition must be of type String or PresentationDefinition"
        }

        clientMetadata?.let {
            require(clientMetadata is ClientMetadata || clientMetadata is String) {
                "clientMetadata must be of type String or ClientMetadata"
            }
        }
    }

    companion object {
        fun validateAndGetAuthorizationRequest(
            encodedAuthorizationRequest: String,
            setResponseUri: (String) -> Unit,
            trustedVerifiers: List<Verifier>,
            shouldValidateClient: Boolean
        ): AuthorizationRequest {

            val queryParameter = extractQueryParams(
                encodedAuthorizationRequest.substring(
                    encodedAuthorizationRequest.indexOf('?') + 1
                )
            )
            val authorizationRequestParams = getAuthorizationRequestObjectMap(
                queryParameter,
                trustedVerifiers,
                shouldValidateClient,
                setResponseUri
            )
            return createAuthorizationRequestObject(authorizationRequestParams)

        }

        private fun getAuthorizationRequestObjectMap(
            params: MutableMap<String, Any>,
            trustedVerifiers: List<Verifier>,
            shouldValidateClient: Boolean,
            setResponseUri: (String) -> Unit
        ): MutableMap<String, Any> {
            val authRequestHandler = getAuthRequestHandler(
                params,
                trustedVerifiers,
                shouldValidateClient,
                setResponseUri
            )
            processAndValidateAuthorizationRequestParameter(authRequestHandler)
            return authRequestHandler.authRequestParam
        }

        private fun processAndValidateAuthorizationRequestParameter(authRequestHandler: ClientIdSchemeBasedAuthRequestHandler) {
            authRequestHandler.validateClientId()
            authRequestHandler.gatherAuthRequest()
            authRequestHandler.gatherInfoForSendingResponseToVerifier()
            authRequestHandler.validateAndParseRequestFields()
        }


        private fun createAuthorizationRequestObject(
            params: Map<String, Any>
        ): AuthorizationRequest {
            return AuthorizationRequest(
                clientId = getStringValue(params, CLIENT_ID.value)!!,
                clientIdScheme = getStringValue(params, CLIENT_ID_SCHEME.value)!!,
                responseType = getStringValue(params, RESPONSE_TYPE.value)!!,
                responseMode = getStringValue(params, RESPONSE_MODE.value),
                presentationDefinition = params[PRESENTATION_DEFINITION.value]!!,
                responseUri = getStringValue(params, RESPONSE_URI.value),
                redirectUri = getStringValue(params, REDIRECT_URI.value),
                nonce = getStringValue(params, NONCE.value)!!,
                state = getStringValue(params, STATE.value)!!,
                clientMetadata = getStringValue(params, CLIENT_METADATA.value),
            )
        }

    }
}