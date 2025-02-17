package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.authRequestHandler.ClientIdSchemeBasedAuthRequestHandler
import io.mosip.openID4VP.authorizationRequest.authRequestHandler.types.DidAuthRequestHandler
import io.mosip.openID4VP.authorizationRequest.authRequestHandler.types.PreRegisteredAuthRequestHandler
import io.mosip.openID4VP.authorizationRequest.authRequestHandler.types.RedirectUriAuthRequestHandler
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

private val className = AuthorizationRequest::class.simpleName!!

fun getAuthRequestHandler(
    params: MutableMap<String, Any>,
    trustedVerifiers: List<Verifier>,
    shouldValidateClient: Boolean,
    setResponseUri: (String) -> Unit
): ClientIdSchemeBasedAuthRequestHandler {
    val clientIdScheme = getStringValue(params,CLIENT_ID_SCHEME.value) ?: ClientIdScheme.PRE_REGISTERED.value
    params[CLIENT_ID_SCHEME.value] = clientIdScheme
    return when (clientIdScheme) {
        ClientIdScheme.PRE_REGISTERED.value -> PreRegisteredAuthRequestHandler(trustedVerifiers, params, shouldValidateClient, setResponseUri)
        ClientIdScheme.REDIRECT_URI.value -> RedirectUriAuthRequestHandler(params, setResponseUri)
        ClientIdScheme.DID.value -> DidAuthRequestHandler(params, setResponseUri)
        else -> throw Logger.handleException(
            exceptionType = "InvalidClientIdScheme",
            className = className,
            message = "Given client_id_scheme is not supported"
        )
    }
}

fun validateKey(
    params: MutableMap<String, Any>,
    key: String,
) {
    val value = getStringValue(params, key)
    if (value == null || value == "null" || value.isEmpty()) {
        throw Logger.handleException(
            exceptionType = if (params[key] == null) "MissingInput" else "InvalidInput",
            fieldPath = listOf(key),
            className = AuthorizationRequest.toString(),
            fieldType = "String"
        )
    }
}

fun extractQueryParams(query: String): MutableMap<String, Any> {
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

fun parseAndValidatePresentationDefinitionInAuthorizationRequest(params: MutableMap<String, Any>): MutableMap<String, Any> {
    val hasPresentationDefinition = params.containsKey(PRESENTATION_DEFINITION.value)
    val hasPresentationDefinitionUri = params.containsKey(PRESENTATION_DEFINITION_URI.value)
    var presentationDefinitionString = ""

    when {
        hasPresentationDefinition && hasPresentationDefinitionUri -> {
            throw Logger.handleException(
                exceptionType = "InvalidQueryParams",
                message = "Either presentation_definition or presentation_definition_uri request param can be provided but not both",
                className = className
            )
        }

        hasPresentationDefinition -> {
            validateKey(params, PRESENTATION_DEFINITION.value)
            presentationDefinitionString = getStringValue(params, PRESENTATION_DEFINITION.value)!!
        }

        hasPresentationDefinitionUri -> {
            try {
                validateKey(params, PRESENTATION_DEFINITION_URI.value)
                presentationDefinitionString =
                    sendHTTPRequest(
                        url = getStringValue(params, PRESENTATION_DEFINITION_URI.value)!!,
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

    val presentationDefinition = deserializeAndValidate((presentationDefinitionString), PresentationDefinitionSerializer)
    params[PRESENTATION_DEFINITION.value] = presentationDefinition

    return params
}

fun parseAndValidateClientMetadataInAuthorizationRequest(params: MutableMap<String, Any>): MutableMap<String, Any> {
    var clientMetadata: ClientMetadata?
    getStringValue(params,CLIENT_METADATA.value)?.let {
        clientMetadata =
            deserializeAndValidate(
                it,
                ClientMetadataSerializer
            )
        params[CLIENT_METADATA.value] = clientMetadata!!
    }
    return params
}

fun validateMatchOfAuthRequestObjectAndParams(
    params: MutableMap<String, Any>,
    authorizationRequestObject: MutableMap<String, Any>,
) {
    if (params[CLIENT_ID.value] != authorizationRequestObject[CLIENT_ID.value]) {
        throw AuthorizationRequestExceptions.InvalidData("Client Id mismatch in Authorization Request parameter and the Request Object")
    }
    if (params[CLIENT_ID_SCHEME.value] != null && params[CLIENT_ID_SCHEME.value] != authorizationRequestObject[CLIENT_ID_SCHEME.value]) {
        throw AuthorizationRequestExceptions.InvalidData("Client Id scheme mismatch in Authorization Request parameter and the Request Object")
    }
}



