package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
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
                val decodedString = Decoder.decodeBase64ToString(encodedString)
                val decodedAuthorizationRequest = encodedAuthorizationRequest.substring(0, queryStart) + decodedString
                val authorizationRequest = parseAuthorizationRequest(decodedAuthorizationRequest)
                validateVerifier(trustedVerifiers, authorizationRequest, shouldValidateClient)
                val params = validateQueryParams(authorizationRequest, setResponseUri)
                return createAuthorizationRequest(params)

            } catch (e: Exception) {
                throw e
            }
        }

        private fun parseAuthorizationRequest(
            decodedAuthorizationRequest: String
        ): MutableMap<String, String> {
            try {
                val queryStart = decodedAuthorizationRequest.indexOf('?') + 1
                val queryString = decodedAuthorizationRequest.substring(queryStart)
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
                return fetchAuthRequestDataMap(params)
            } catch (exception: Exception) {
                Logger.error(logTag, exception)
                throw exception
            }
        }

        private fun fetchAuthRequestDataMap(params: MutableMap<String, String>): MutableMap<String, String> {
            return params["request_uri"]?.let { requestUri ->
                return fetchAuthRequestObjectByReference(params, requestUri)
            } ?: params
        }

        private fun fetchAuthRequestObjectByReference(
            params: MutableMap<String, String>,
            requestUri: String,
        ): MutableMap<String, String> {
            try {
                val requestUriMethod = params["request_uri_method"] ?: "get"
                validateRootFieldInvalidScenario("request_uri", requestUri)
                validateRootFieldInvalidScenario("request_uri_method", requestUriMethod)
                val httpMethod = determineHttpMethod(requestUriMethod)
                val response = sendHTTPRequest(requestUri, httpMethod)
                val authorizationRequestObject = extractAuthRequestData(response, params)
                return authorizationRequestObject
            } catch (exception: Exception) {
                println("Exception is $exception")
                throw exception
            }
        }

        private fun extractAuthRequestData(
            response: String,
            params: MutableMap<String, String>
        ): MutableMap<String, String> {
            val authorizationRequestObject: MutableMap<String, String>
            if (isJWT(response)) {
                authorizationRequestObject = extractDataJsonFromJwt(response, PAYLOAD)
                validateMatchOfAuthRequestObjectAndParams(params, authorizationRequestObject)
                val proof = ProofJwtManager()
                proof.verifyJWT(
                    response,
                    authorizationRequestObject["client_id"]!!,
                    authorizationRequestObject["client_id_scheme"]!!
                )
            } else {
                authorizationRequestObject = decodeBase64ToJSON(response)
                validateMatchOfAuthRequestObjectAndParams(params, authorizationRequestObject)
            }
            return authorizationRequestObject
        }

        private fun validateMatchOfAuthRequestObjectAndParams(
            params: MutableMap<String, String>,
            authorizationRequestObject: MutableMap<String, String>,
        ) {
            if (params["client_id"] != authorizationRequestObject["client_id"]) {
                throw AuthorizationRequestExceptions.InvalidData("Client Id mismatch in Authorization Request parameter and the Request Object")
            }
            if (params["client_id_scheme"] != null && params["client_id_scheme"] != authorizationRequestObject["client_id_scheme"]) {
                throw AuthorizationRequestExceptions.InvalidData("Client Id scheme mismatch in Authorization Request parameter and the Request Object")
            }
        }

        private fun createAuthorizationRequest(params: Map<String, String>): AuthorizationRequest {
            return AuthorizationRequest(
                clientId = params["client_id"]!!,
                clientIdScheme = params["client_id_scheme"]!!,
                responseType = params["response_type"]!!,
                responseMode = params["response_mode"],
                presentationDefinition = params["presentation_definition"]!!,
                responseUri = params["response_uri"],
                redirectUri = params["redirect_uri"],
                nonce = params["nonce"]!!,
                state = params["state"]!!,
                clientMetadata = params["client_metadata"],
            )
        }

    }
}