package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.common.Decoder
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.validateField
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest

import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.core.type.TypeReference
import io.mosip.openID4VP.authorizationRequest.proofJwt.ProofJwtManager

private val className = AuthorizationRequest::class.simpleName!!
private val logTag = Logger.getLogTag(className)
private var authorizationRequest: MutableMap<String, String> = mutableMapOf()
private var validateClient: Boolean = false;

enum class ClientIdScheme(val value: String) {
    PRE_REGISTERED("pre-registered"),
    REDIRECT_URI("redirect_uri")
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
                val decodedString =
                    Decoder.decodeBase64ToString(encodedString)
                val decodedAuthorizationRequest =
                    encodedAuthorizationRequest.substring(0, queryStart) + decodedString;
                validateClient = shouldValidateClient
                authorizationRequest =
                    parseAuthorizationRequest(decodedAuthorizationRequest, setResponseUri)

                if (validateClient) {
                    validateVerifier(
                        trustedVerifiers, authorizationRequest
                    )
                }
                val params = validateQueryParams(authorizationRequest, setResponseUri)
                return createAuthorizationRequest(params)

            } catch (e: Exception) {
                throw e
            }
        }

        private fun validateVerifier(
            verifierList: List<Verifier>,
            authorizationRequest: MutableMap<String, String>
        ) {
            val clientIdScheme = authorizationRequest["client_id_scheme"]
            val clientId = authorizationRequest["client_id"]
            val redirectUri = authorizationRequest["redirect_uri"]

            when (clientIdScheme) {
                ClientIdScheme.PRE_REGISTERED.value -> {
                    if (verifierList.isEmpty()) {
                        throw Logger.handleException(
                            exceptionType = "EmptyVerifierList",
                            className = AuthorizationRequest.toString()
                        )
                    }
                    val isValidVerifier = verifierList.any { verifier ->
                        verifier.clientId == clientId &&
                                verifier.responseUris.contains(authorizationRequest["response_uri"])
                    }
                    if (!isValidVerifier) {
                        throw Logger.handleException(
                            exceptionType = "InvalidVerifierClientID",
                            className = AuthorizationRequest.toString()
                        )
                    }
                }

                ClientIdScheme.REDIRECT_URI.value -> {
                    if (redirectUri != null && redirectUri != clientId) {
                        throw Logger.handleException(
                            exceptionType = "InvalidVerifierRedirectUri",
                            className = AuthorizationRequest.toString()
                        )
                    }
                }
            }
        }

        private fun parseAuthorizationRequest(
            decodedAuthorizationRequest: String, setResponseUri: (String) -> Unit
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
                return fetchAuthRequestData(params)
            } catch (exception: Exception) {
                Logger.error(logTag, exception)
                throw exception
            }
        }

        private fun fetchAuthRequestData(params: MutableMap<String, String>): MutableMap<String, String> {
            return params["request_uri"]?.let { requestUri ->
                try {
                    val requestUriMethod = params["request_uri_method"] ?: "get HTTP/1.1"
                    validateRootFieldInvalidScenario("request_uri", params["request_uri"])
                    validateRootFieldInvalidScenario("request_uri_method", requestUriMethod)
                    val httpMethod = determineHttpMethod(requestUriMethod)

                    val response =
                        "eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6d2ViOmFkaXR5YW5rYW5uYW4tdHcuZ2l0aHViLmlvOm9wZW5pZDR2cDpmaWxlcyNrZXktMCJ9.eyJjbGllbnRfaWQiOiJkaWQ6d2ViOmFkaXR5YW5rYW5uYW4tdHcuZ2l0aHViLmlvOm9wZW5pZDR2cDpmaWxlcyIsImNsaWVudF9pZF9zY2hlbWUiOiJkaWQiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJyZWRpcmVjdF91cmkiOiJodHRwczovL2NsaWVudC5leGFtcGxlLm9yZy9jYWxsYmFjayIsIm5vbmNlIjoibi0wUzZfV3pBMk1qIiwic3RhdGUiOiJuZTI5MmV3d2l3aWl3aSIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjoie1wiaWRcIjpcIjEyM1wiLFwiaW5wdXRfZGVzY3JpcHRvcnNcIjpbe1wiaWRcIjpcImJhbmtpbmdfaW5wdXRfMVwiLFwiZm9ybWF0XCI6e1wibGRwX3ZjXCI6e1wicHJvb2ZfdHlwZVwiOltcIkVkMjU1MTlTaWduYXR1cmUyMDE4XCJdfX0sXCJuYW1lXCI6XCJCYW5rQWNjb3VudEluZm9ybWF0aW9uXCIsXCJwdXJwb3NlXCI6XCJoaWlpaVwiLFwiY29uc3RyYWludHNcIjp7XCJmaWVsZHNcIjpbe1wicGF0aFwiOltcIiQuY3JlZGVcIl0sXCJwdXJwb3NlXCI6XCJXZWNhbnVzZWZvciN2ZXJpZmljYXRpb25wdXJwb3NlI2ZvcmFueXRoaW5nXCIsXCJmaWx0ZXJcIjp7XCJ0eXBlXCI6XCJzdHJpbmdcIixcInBhdHRlcm5cIjpcIl5bMC05XXs5fXxeKFthLXpBLVpdKXs0fShbYS16QS1aXSl7Mn0oWzAtOWEtekEtWl0pezJ9KFswLTlhLXpBLVpdezN9KT8kXCJ9fSx7XCJwYXRoXCI6W1wiJC52Yy5jcmVkZW50aWFsXCIsXCIkLnZjLmNyZWRlbnRpYWxTdWJqZWN0LmFjY291bnRbKl0ucm91dGVcIixcIiQuYWNjb3VudFsqXS5yb3V0ZVwiXSxcInB1cnBvc2VcIjpcIldlY2FudXNlZm9ydmVyaWZpY2F0aW9ucHVycG9zZVwiLFwiZmlsdGVyXCI6e1widHlwZVwiOlwic3RyaW5nXCIsXCJwYXR0ZXJuXCI6XCJeWzAtOV17OX18XihbYS16QS1aXSl7NH0oW2EtekEtWl0pezJ9KFswLTlhLXpBLVpdKXsyfShbMC05YS16QS1aXXszfSk_JFwifX1dfX1dfSIsImNsaWVudF9tZXRhZGF0YSI6IntcImNsaWVudF9uYW1lXCI6XCJhZGl0eWFuXCJ9In0.l12/pXHDNaGiBDsHAJAn52DFZ1rzAuEpOsPZOt9k/0l9LBTN9SSAe0HXFKN+eoeDygo1d05kSW08Ob8SCUz6Dg==";
                    return processResponseAndFetchAuthRequestParams(response)
                } catch (exception: Exception) {
                    throw exception
                }
            } ?: params
        }

        private fun determineHttpMethod(method: String?): HTTP_METHOD {
            return when {
                method?.contains("get") == true -> HTTP_METHOD.GET
                method?.contains("post") == true -> HTTP_METHOD.POST
                else -> throw IllegalArgumentException("Unsupported HTTP method: $method")
            }
        }

        private fun processResponseAndFetchAuthRequestParams(authorizationRequest: String): MutableMap<String, String> {

            if (isJWT(authorizationRequest)) {
                val params = extractPayloadJsonFromJwt(authorizationRequest)
                if (validateClient) {
                    val Proof = ProofJwtManager()
                    Proof.verifyJWT(
                        authorizationRequest,
                        params["client_id"]!!,
                        params["client_id_scheme"]!!
                    )
                }
                return params
            } else {
                return decodeBase64ToJSON(authorizationRequest)
            }
        }

        private fun extractPayloadJsonFromJwt(jwtToken: String): MutableMap<String, String> {
            val components = jwtToken.split(".")
            if (components.size < 2) throw IllegalArgumentException("Invalid JWT token format")

            val payload = components[1]
            val standardizedBase64 = makeBase64Standard(payload)
            return decodeBase64ToJSON(standardizedBase64)
        }

        private fun makeBase64Standard(base64String: String): String {
            var base64 = base64String
                .replace("-", "+")
                .replace("_", "/")

            while (base64.length % 4 != 0) {
                base64 += "="
            }
            return base64
        }

        private fun decodeBase64ToJSON(base64String: String): MutableMap<String, String> {
            val decodedString = try {
                Decoder.decodeBase64ToString(base64String)
            } catch (e: IllegalArgumentException) {
                throw Exception("JWT payload decoding failed: ${e.message}")
            }
            return convertJsonToMap(decodedString)
        }

        fun convertJsonToMap(jsonString: String): MutableMap<String, String> {
            val mapper = jacksonObjectMapper()
            return mapper.readValue(
                jsonString,
                object : TypeReference<MutableMap<String, String>>() {})
        }

        private fun isJWT(authorizationRequest: String): Boolean {
            return authorizationRequest.contains(".")
        }

        private fun extractQueryParams(query: String): MutableMap<String, String> {
            try {
                return query.split("&").map { it.split("=") }
                    .associateByTo(mutableMapOf(), { it[0] }, {
                        if (it.size > 1) URLDecoder.decode(
                            it[1], StandardCharsets.UTF_8.toString()
                        ) else ""
                    })
            } catch (exception: Exception) {
                throw Logger.handleException(
                    exceptionType = "InvalidQueryParams",
                    message = "Exception occurred when extracting the query params from Authorization Request : ${exception.message}",
                    className = className
                )
            }
        }

        private fun fetchPresentationDefinition(params: Map<String, String>): String {
            val hasPresentationDefinition = params.containsKey("presentation_definition")
            val hasPresentationDefinitionUri = params.containsKey("presentation_definition_uri")
            var presentationDefinition = ""

            when {
                hasPresentationDefinition && hasPresentationDefinitionUri -> {
                    throw Logger.handleException(
                        exceptionType = "InvalidQueryParams",
                        message = "Either presentation_definition or presentation_definition_uri request param can be provided but not both",
                        className = className
                    )
                }

                hasPresentationDefinition -> {
                    val value = params["presentation_definition"]

                    require(value != "null" && validateField(value, "String")) {
                        throw Logger.handleException(
                            exceptionType = "InvalidInput",
                            fieldPath = listOf("presentation_definition"),
                            className = className,
                            fieldType = "String"
                        )
                    }
                    presentationDefinition =
                        params["presentation_definition"]!!
                }

                hasPresentationDefinitionUri -> {
                    try {
                        validateRootFieldInvalidScenario(
                            "presentation_definition_uri",
                            params["presentation_definition_uri"]
                        )
                        presentationDefinition =
                            sendHTTPRequest(
                                url = params["presentation_definition_uri"]!!,
                                method = HTTP_METHOD.GET
                            )
                    } catch (exception: Exception) {
                        throw exception
                    }
                }

                else -> {
                    throw Logger.handleException(
                        exceptionType = "InvalidQueryParams",
                        message = "Either presentation_definition or presentation_definition_uri request param must be present",
                        className = className
                    )
                }
            }
            return presentationDefinition
        }

        private fun baseRequiredKeys(params: Map<String, String>): MutableList<String> {
            val keys = mutableListOf(
                "presentation_definition",
                "client_id",
                "client_id_scheme",
                "response_type",
                "nonce",
                "state"
            )

            if (params.containsKey("client_metadata")) {
                keys.add("client_metadata")
            }
            return keys
        }

        private fun validateUriCombinations(
            redirectUri: String?,
            responseUri: String?,
            responseMode: String?
        ) {
            val allNil = redirectUri == null && responseUri == null && responseMode == null
            val allPresent = redirectUri != null && responseUri != null && responseMode != null

            if (allNil) {
                throw Logger.handleException(
                    exceptionType = "MissingInput",
                    fieldPath = listOf("response_uri", "response_mode", "redirect_uri"),
                    className = AuthorizationRequest.toString()
                )
            }
            if (allPresent) {
                throw Logger.handleException(
                    exceptionType = "InvalidInput",
                    fieldPath = listOf("response_uri", "response_mode", "redirect_uri"),
                    className = AuthorizationRequest.toString()
                )
            }
        }

        private fun updateRequiredKeys(
            requiredKeys: MutableList<String>,
            redirectUri: String?,
            responseUri: String?,
            responseMode: String?
        ) {
            if (redirectUri != null && responseUri == null && responseMode == null) {
                requiredKeys.add("redirect_uri")
            }
            if (responseUri != null && responseMode != null && redirectUri == null) {
                requiredKeys.addAll(listOf("response_uri", "response_mode"))
            }
        }

        private fun validateKey(
            key: String,
            values: MutableMap<String, String>,
            setResponseUri: (String) -> Unit
        ) {
            if (key == "presentation_definition") {
                values[key] = fetchPresentationDefinition(params = values)
            }

            val value = values[key]
            if (value == null || value == "null" || value.isEmpty()) {
                throw Logger.handleException(
                    exceptionType = if (values[key] == null) "MissingInput" else "InvalidInput",
                    fieldPath = listOf(key),
                    className = AuthorizationRequest.toString()
                )
            }
            if (key == "response_uri") {
                setResponseUri(value)
            }
        }

        private fun validateQueryParams(
            params: MutableMap<String, String>, setResponseUri: (String) -> Unit
        ): MutableMap<String, String> {
            val baseRequiredFields = baseRequiredKeys(params)
            try {
                validateUriCombinations(
                    params["redirect_uri"],
                    params["response_uri"],
                    params["response_mode"]
                )
                updateRequiredKeys(
                    baseRequiredFields,
                    params["redirect_uri"],
                    params["response_uri"],
                    params["response_mode"]
                )

                for (key in baseRequiredFields) {
                    validateKey(key, params, setResponseUri)
                }
                return params
            } catch (exception: Exception) {
                throw exception
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

        private fun validateRootFieldMissingScenario(
            params: MutableMap<String, String>,
            param: String
        ) {
            val hasParam = params.containsKey(param)
            if (!hasParam) {
                throw Logger.handleException(
                    exceptionType = "MissingInput",
                    fieldPath = listOf(param),
                    className = className
                )
            }
        }

        private fun validateRootFieldInvalidScenario(param: String, value: String?) {
            require(value != "null" && validateField(value, "String")) {
                throw Logger.handleException(
                    exceptionType = "InvalidInput",
                    fieldPath = listOf(param),
                    className = className,
                    fieldType = "String"
                )
            }
        }
    }
}