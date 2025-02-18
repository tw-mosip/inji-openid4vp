package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.common.Decoder
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.dto.Verifier
import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

enum class ClientIdScheme(val value: String) {
    PRE_REGISTERED("pre-registered"),
    REDIRECT_URI("redirect_uri"),
    DID("did")
}

private val className = AuthorizationRequest::class.simpleName!!
private val logTag = Logger.getLogTag(className)

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

        fun validateAndCreateAuthorizationRequest(
            encodedAuthorizationRequest: String,
            trustedVerifiers: List<Verifier>,
            setResponseUri: (String) -> Unit,
            shouldValidateClient: Boolean
        ): AuthorizationRequest {
            try {
                val queryStart = encodedAuthorizationRequest.indexOf('?') + 1
                val encodedString = encodedAuthorizationRequest.substring(queryStart)
                val decodedQueryString = Decoder.decodeBase64ToString(encodedString)
                return parseAuthorizationRequest(decodedQueryString,setResponseUri,trustedVerifiers,shouldValidateClient)
            } catch (e: Exception) {
                throw e
            }
        }

        private fun parseAuthorizationRequest(
            queryString: String,
            setResponseUri: (String) -> Unit,
            trustedVerifiers: List<Verifier>,
            shouldValidateClient: Boolean
        ): AuthorizationRequest {
            try {
                val encodedQuery = URLEncoder.encode(queryString, StandardCharsets.UTF_8.toString())
                val uriString = "?$encodedQuery"
                val uri = URI(uriString)
                val query = uri.query
                    ?: throw Logger.handleException(
                        exceptionType = "InvalidQueryParams",
                        message = "Query parameters are missing in the Authorization request",
                        className = className
                    )
                val params = extractQueryParameters(query)
                return getAuthorizationRequestObject(
                    params,
                    trustedVerifiers,
                    shouldValidateClient,
                    setResponseUri
                )
            } catch (exception: Exception) {
                Logger.error(logTag, exception)
                throw exception
            }
        }


        private fun getAuthorizationRequestObject(
            params: MutableMap<String, Any>,
            trustedVerifiers: List<Verifier>,
            shouldValidateClient: Boolean,
            setResponseUri: (String) -> Unit
        ): AuthorizationRequest {
            val authRequestHandler = getAuthorizationRequestHandler(
                params,
                trustedVerifiers,
                setResponseUri,
                shouldValidateClient
            )
            processAndValidateAuthorizationRequestParameter(authRequestHandler)
            return authRequestHandler.createAuthorizationRequestObject()
        }

        private fun processAndValidateAuthorizationRequestParameter(authorizationRequestHandler: ClientIdSchemeBasedAuthorizationRequestHandler) {
            authorizationRequestHandler.validateClientId()
            authorizationRequestHandler.fetchAuthorizationRequest()
            authorizationRequestHandler.setResponseUrlForSendingResponseToVerifier()
            authorizationRequestHandler.validateAndParseRequestFields()
        }




    }
}