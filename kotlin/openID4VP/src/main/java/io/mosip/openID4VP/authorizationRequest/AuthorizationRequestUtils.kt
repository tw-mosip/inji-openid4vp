package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.validateField
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

private val className = AuthorizationRequest::class.simpleName!!

fun validateVerifier(
    verifierList: List<Verifier>,
    authorizationRequest: MutableMap<String, String>,
    shouldValidateVerifier: Boolean
) {
    val clientIdScheme = authorizationRequest["client_id_scheme"]
    val clientId = authorizationRequest["client_id"]
    val redirectUri = authorizationRequest["redirect_uri"]

    when (clientIdScheme) {
        ClientIdScheme.PRE_REGISTERED.value -> {
            if (shouldValidateVerifier) {
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
        }
        ClientIdScheme.REDIRECT_URI.value -> {
            if(authorizationRequest["response_uri"]!=null && authorizationRequest["response_mode"] != null){
                throw Logger.handleException(
                    exceptionType = "InvalidQueryParams",
                    className = AuthorizationRequest.toString(),
                    message = "Response Uri and Response mode should not be present, when client id scheme is Redirect Uri"
                )
            }
            if (redirectUri != null && redirectUri != clientId) {
                throw Logger.handleException(
                    exceptionType = "InvalidVerifierRedirectUri",
                    className = AuthorizationRequest.toString(),
                    message = "Client id and redirect_uri value should be equal"
                )
            }
        }


    }
}
fun validateUriCombinations(
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

fun updateRequiredKeys(
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

fun validateKey(
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
            className = AuthorizationRequest.toString(),
            fieldType = "String"
        )
    }
    if (key == "response_uri") {
        setResponseUri(value)
    }
}

fun validateQueryParams(
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

fun extractQueryParams(query: String): MutableMap<String, String> {
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

fun fetchPresentationDefinition(params: Map<String, String>): String {
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
            val presentationDefinitionValue = params["presentation_definition"]
            validateRootFieldInvalidScenario(
                "presentation_definition",
                presentationDefinitionValue
            )
            presentationDefinition = presentationDefinitionValue!!
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

fun baseRequiredKeys(params: Map<String, String>): MutableList<String> {
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

// TODO: validateRootFieldInvalidScenario is validating only string field type, can method be named accordingly
fun validateRootFieldInvalidScenario(param: String, value: String?) {
    require(value != "null" && validateField(value, "String")) {
        throw Logger.handleException(
            exceptionType = "InvalidInput",
            fieldPath = listOf(param),
            className = className,
            fieldType = "String"
        )
    }
}

