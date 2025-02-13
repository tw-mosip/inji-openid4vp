package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.authorizationRequest.proofJwt.ProofJwtManager
import io.mosip.openID4VP.authorizationRequest.proofJwt.didHandler.DidUtils.JwtPart.PAYLOAD
import io.mosip.openID4VP.common.Decoder
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.decodeBase64ToJSON
import io.mosip.openID4VP.common.determineHttpMethod
import io.mosip.openID4VP.common.extractDataJsonFromJwt
import io.mosip.openID4VP.common.isJWT
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

private val className = AuthorizationRequest::class.simpleName!!
private val logTag = Logger.getLogTag(className)

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
            try {
                val queryStart = encodedAuthorizationRequest.indexOf('?') + 1
                val encodedString = encodedAuthorizationRequest.substring(queryStart)
                val decodedQueryString = Decoder.decodeBase64ToString(encodedString)
                val authorizationRequestParams = parseAuthorizationRequest(decodedQueryString)
                validateVerifier(trustedVerifiers, authorizationRequestParams, shouldValidateClient)
                validateAuthorizationRequestParams(authorizationRequestParams, setResponseUri)
                return createAuthorizationRequest(authorizationRequestParams)
            } catch (e: Exception) {
                throw e
            }
        }

        private fun parseAuthorizationRequest(
            queryString: String
        ): MutableMap<String, Any> {
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
                val params = extractQueryParams(query)
                return fetchAuthorizationRequestMap(params)
            } catch (exception: Exception) {
                Logger.error(logTag, exception)
                throw exception
            }
        }

        private fun fetchAuthorizationRequestMap(
            params: MutableMap<String, Any>
        ): MutableMap<String, Any> {
            var authorizationRequestMap =  getValue(params,"request_uri")?.let { requestUri ->
                 fetchAuthRequestObjectByReference(params, requestUri)
            } ?: params

            authorizationRequestMap = parseAndValidateClientMetadataInAuthorizationRequest(authorizationRequestMap)
            authorizationRequestMap = parseAndValidatePresentationDefinitionInAuthorizationRequest(authorizationRequestMap)
            return authorizationRequestMap
        }

        private fun fetchAuthRequestObjectByReference(
            params: MutableMap<String, Any>,
            requestUri: String,
        ): MutableMap<String, Any> {
            try {
                val requestUriMethod = getValue(params, "request_uri_method") ?: "get"
                validateRootFieldInvalidScenario("request_uri", requestUri)
                validateRootFieldInvalidScenario("request_uri_method", requestUriMethod)
                val httpMethod = determineHttpMethod(requestUriMethod)
                val response = sendHTTPRequest(requestUri, httpMethod)
                val authorizationRequestObject = extractAuthorizationRequestData(response, params)
                return authorizationRequestObject
            } catch (exception: Exception) {
                println("Exception is $exception")
                throw exception
            }
        }

        private fun extractAuthorizationRequestData(
            response: String,
            params: MutableMap<String, Any>
        ): MutableMap<String, Any> {
            val authorizationRequestObject: MutableMap<String, Any>
            if (isJWT(response)) {
                authorizationRequestObject = extractDataJsonFromJwt(response, PAYLOAD)
                validateMatchOfAuthRequestObjectAndParams(params, authorizationRequestObject)
                val proof = ProofJwtManager()
                val clientId = getValue(authorizationRequestObject, "client_id")
                val clientIdScheme = extractClientIdScheme(clientId!!)
                proof.verifyJWT(
                    response,
                    clientId,
                    clientIdScheme,
                )
            } else {
                authorizationRequestObject = decodeBase64ToJSON(response)
                validateMatchOfAuthRequestObjectAndParams(params, authorizationRequestObject)
            }
            return authorizationRequestObject
        }

        private fun createAuthorizationRequest(
            params: Map<String, Any>
        ): AuthorizationRequest {
            val clientId = getValue(params, "client_id")!!
            return AuthorizationRequest(
                clientId = clientId,
                clientIdScheme = extractClientIdScheme(clientId),
                responseType = getValue(params, "response_type")!!,
                responseMode = getValue(params, "response_mode"),
                presentationDefinition = params["presentation_definition"]!!,
                responseUri = getValue(params,"response_uri"),
                redirectUri = getValue(params,"redirect_uri"),
                nonce = getValue(params,"nonce")!!,
                state = getValue(params, "state")!!,
                clientMetadata = getValue(params, "client_metadata"),
            )
        }

    }
}