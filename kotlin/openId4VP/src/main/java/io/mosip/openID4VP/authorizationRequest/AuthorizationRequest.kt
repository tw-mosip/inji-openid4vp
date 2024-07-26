package io.mosip.openID4VP.authorizationRequest

import android.net.Uri
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.shared.Decoder

class AuthorizationRequest(
    val clientId: String,
    val responseType: String,
    val responseMode: String,
    val presentationDefinition: String,
    val responseUri: String,
    val nonce: String,
    val state: String
) {
    companion object {
        fun getAuthorizationRequest(encodedAuthorizationRequest: String):AuthorizationRequest{
            try {
                val decodedAuthorizationRequest = Decoder.decodeBase64ToString(encodedAuthorizationRequest)
                return parseAuthorizationRequest(decodedAuthorizationRequest)
            }catch (e: AuthorizationRequestExceptions.DecodingException){
                throw e
            }catch (e: IllegalArgumentException){
                throw e
            }
        }


        private fun parseAuthorizationRequest(decodedAuthorizationRequest: String): AuthorizationRequest {
            try {
                val requiredQueryParams = listOf(
                    "client_id",
                    "response_type",
                    "response_mode",
                    "presentation_definition",
                    "response_uri",
                    "nonce",
                    "state"
                )

                with(Uri.parse("?$decodedAuthorizationRequest")) {
                    val receivedQueryParams =
                        queryParameterNames.associateWith { getQueryParameter(it) }

                    val extractedParams = mutableMapOf<String, String>()
                    for (paramName in requiredQueryParams) {
                        when (val value = receivedQueryParams[paramName]) {
                            null -> throw IllegalArgumentException("$paramName request param is missing")
                            "null" -> throw IllegalArgumentException("$paramName request param value is null")
                            "" -> throw IllegalArgumentException("$paramName request param value is empty")
                            else -> extractedParams[paramName] = value
                        }
                    }

                    return AuthorizationRequest(
                        clientId = extractedParams["client_id"] as String,
                        responseType = extractedParams["response_type"]
                                as String,
                        responseMode = extractedParams["response_mode"] as String,
                        presentationDefinition = extractedParams["presentation_definition"]
                                as String,
                        responseUri = extractedParams["response_uri"] as String,
                        nonce = extractedParams["nonce"]
                                as String,
                        state = extractedParams["state"] as String
                    )
                }

            }catch (e: IllegalArgumentException){
                throw e
            }
        }
    }
}