package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.common.Decoder
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import isNeitherNullNorEmpty
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

private val logTag = Logger.getLogTag(AuthorizationRequest::class.simpleName!!)
private val className = AuthorizationRequest::class.simpleName!!

data class AuthorizationRequest(
    val clientId: String,
    val responseType: String,
    val responseMode: String,
    var presentationDefinition: Any,
    val responseUri: String,
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
            encodedAuthorizationRequest: String, setResponseUri: (String) -> Unit
        ): AuthorizationRequest {
            try {
                val queryStart = encodedAuthorizationRequest.indexOf('?') + 1
                val encodedString = encodedAuthorizationRequest.substring(queryStart)
                val decodedString =
                    Decoder.decodeBase64ToString(encodedString)
                val decodedAuthorizationRequest =
                    encodedAuthorizationRequest.substring(0, queryStart) + decodedString
                return parseAuthorizationRequest(decodedAuthorizationRequest, setResponseUri)
            } catch (e: Exception) {
                throw e
            }
        }

        private fun parseAuthorizationRequest(
            decodedAuthorizationRequest: String, setResponseUri: (String) -> Unit
        ): AuthorizationRequest {
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
                validateQueryParams(params, setResponseUri)
                return createAuthorizationRequest(params)
            } catch (exception: Exception) {
                Logger.error(logTag, exception)
                throw exception
            }
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
                    val value = params["presentation_definition"] ?: throw Logger.handleException(
                        exceptionType = "MissingInput",
                        fieldPath = listOf("presentation_definition"),
                        className = className
                    )
                    require(isNeitherNullNorEmpty(value)) {
                        throw Logger.handleException(
                            exceptionType = "InvalidInput",
                            fieldPath = listOf("presentation_definition"),
                            className = className
                        )
                    }
                    presentationDefinition =
                        params["presentation_definition"]!!
                }

                hasPresentationDefinitionUri -> {
                    try {
                        val value =
                            params["presentation_definition_uri"] ?: throw Logger.handleException(
                                exceptionType = "MissingInput",
                                fieldPath = listOf("presentation_definition_uri"),
                                className = className
                            )
                        require(isNeitherNullNorEmpty(value)) {
                            throw Logger.handleException(
                                exceptionType = "InvalidInput",
                                fieldPath = listOf("presentation_definition_uri"),
                                className = className
                            )
                        }
                        presentationDefinition =
                            sendHTTPRequest(
                                url = params["presentation_definition_uri"]!!,
                                method = HTTP_METHOD.GET
                            )
                    } catch (exception: Exception) {
                        throw exception
                    }
                }

                !hasPresentationDefinitionUri -> {
                    throw Logger.handleException(
                        exceptionType = "InvalidQueryParams",
                        message = "Either presentation_definition or presentation_definition_uri request param must be present",
                        className = className
                    )
                }
            }
            return presentationDefinition
        }

        private fun validateQueryParams(
            params: MutableMap<String, String>, setResponseUri: (String) -> Unit
        ) {
            val responseUri = params["response_uri"]
            if (responseUri == null) {
                throw Logger.handleException(
                    exceptionType = "MissingInput",
                    fieldPath = listOf("response_uri"),
                    className = className
                )
            } else if (!isNeitherNullNorEmpty(responseUri)) {
                throw Logger.handleException(
                    exceptionType = "InvalidInput",
                    fieldPath = listOf("response_uri"),
                    className = className
                )
            } else {
                setResponseUri(responseUri)
            }

            val requiredRequestParams = mutableListOf(
                "presentation_definition",
                "client_id",
                "response_type",
                "response_mode",
                "nonce",
                "state",
            )
            requiredRequestParams.forEach { param ->
                if (param == "presentation_definition") {
                    try {
                        params["presentation_definition"] = fetchPresentationDefinition(params)
                    } catch (exception: Exception) {
                        throw exception
                    }
                }
                val value = params[param] ?: throw Logger.handleException(
                    exceptionType = "MissingInput",
                    fieldPath = listOf(param),
                    className = className
                )
                require(isNeitherNullNorEmpty(value)) {
                    throw Logger.handleException(
                        exceptionType = "InvalidInput",
                        fieldPath = listOf(param),
                        className = className
                    )
                }
            }

            val optionalRequestParams = mutableListOf("client_metadata")
            optionalRequestParams.forEach { param ->
                params[param]?.let { value ->
                    require(value.isNotEmpty()) {
                        throw AuthorizationRequestExceptions.InvalidInput(param)
                    }
                }
            }
        }

        private fun createAuthorizationRequest(params: Map<String, String>): AuthorizationRequest {
            return AuthorizationRequest(
                clientId = params["client_id"]!!,
                responseType = params["response_type"]!!,
                responseMode = params["response_mode"]!!,
                presentationDefinition = params["presentation_definition"]!!,
                responseUri = params["response_uri"]!!,
                nonce = params["nonce"]!!,
                state = params["state"]!!,
                clientMetadata = params["client_metadata"],
            )
        }
    }
}