package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.OpenId4VP
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.common.Decoder
import io.mosip.openID4VP.common.Logger
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

private val logTag = Logger.getLogTag(AuthorizationRequest::class.simpleName!!)

class AuthorizationRequest(
    val clientId: String,
    val responseType: String,
    val responseMode: String,
    val presentationDefinition: String?,
    val scope: String?,
    val responseUri: String,
    val nonce: String,
    val state: String
) {
    companion object {
        fun getAuthorizationRequest(
            encodedAuthorizationRequest: String, openId4VP: OpenId4VP
        ): AuthorizationRequest {
            try {
                val decodedAuthorizationRequest =
                    Decoder.decodeBase64ToString(encodedAuthorizationRequest)
                return parseAuthorizationRequest(decodedAuthorizationRequest, openId4VP)
            } catch (e: Exception) {
                throw e
            }
        }

        private fun parseAuthorizationRequest(
            decodedAuthorizationRequest: String, openId4VP: OpenId4VP
        ): AuthorizationRequest {
            try {
                val queryStart = decodedAuthorizationRequest.indexOf('?') + 1
                val queryString = decodedAuthorizationRequest.substring(queryStart)
                val encodedQuery = URLEncoder.encode(queryString, StandardCharsets.UTF_8.toString())
                val uriString = "OPENID4VP://authorize?$encodedQuery"
                val uri = URI(uriString)
                val query = uri.query
                    ?: throw AuthorizationRequestExceptions.InvalidQueryParams("Query parameters are missing in the Authorization request")

                val params = extractQueryParams(query)
                validateRequiredParams(params, openId4VP)
                return createAuthorizationRequest(params)
            } catch (exception: Exception) {
                Logger.error(logTag, exception)
                throw exception
            }
        }

        private fun extractQueryParams(query: String): Map<String, String> {
            try {
                return query.split("&").map { it.split("=") }.associateBy({ it[0] }, {
                        if (it.size > 1) URLDecoder.decode(
                            it[1], StandardCharsets.UTF_8.toString()
                        ) else ""
                    })
            } catch (exception: Exception) {
                throw AuthorizationRequestExceptions.InvalidQueryParams("Exception occurred when extracting the query params from Authorization Request : ${exception.message}")
            }
        }

        private fun validateRequiredParams(params: Map<String, String>, openId4VP: OpenId4VP) {
            val requiredRequestParams = mutableListOf(
                "response_uri",
                "client_id",
                "response_type",
                "response_mode",
                "nonce",
                "state",
            )


            val hasPresentationDefinition = params.containsKey("presentation_definition")
            val hasScope = params.containsKey("scope")

            when {
                hasPresentationDefinition && hasScope -> throw AuthorizationRequestExceptions.InvalidQueryParams(
                    "Only one of presentation_definition or scope request param can be present"
                )
                hasPresentationDefinition -> requiredRequestParams.add("presentation_definition")
                hasScope -> requiredRequestParams.add("scope")
                else -> throw AuthorizationRequestExceptions.InvalidQueryParams("Either presentation_definition or scope request param must be present")
            }
            requiredRequestParams.forEach { param ->
                val value =
                    params[param] ?: throw AuthorizationRequestExceptions.MissingInput(param)
                if (param == "response_uri") {
                    openId4VP.responseUri = value
                }
                require(value.isNotEmpty()) {
                    AuthorizationRequestExceptions.InvalidInput(param)
                }
            }
        }

        private fun createAuthorizationRequest(params: Map<String, String>): AuthorizationRequest {
            return AuthorizationRequest(
                clientId = params["client_id"]!!,
                responseType = params["response_type"]!!,
                responseMode = params["response_mode"]!!,
                presentationDefinition = params["presentation_definition"],
                scope = params["scope"],
                responseUri = params["response_uri"]!!,
                nonce = params["nonce"]!!,
                state = params["state"]!!
            )
        }
    }
}