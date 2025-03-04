package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types.*
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.isValidUrl
import io.mosip.openID4VP.dto.Verifier
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

private val className = AuthorizationRequest::class.simpleName!!

fun getAuthorizationRequestHandler(
    authorizationRequestParameters: MutableMap<String, Any>,
    trustedVerifiers: List<Verifier>,
    setResponseUri: (String) -> Unit,
    shouldValidateClient: Boolean
): ClientIdSchemeBasedAuthorizationRequestHandler {
    validateAttribute(authorizationRequestParameters, CLIENT_ID.value)

    val clientIdScheme = extractClientIdScheme(getStringValue(authorizationRequestParameters,CLIENT_ID.value)!!)
    return when (clientIdScheme) {
        ClientIdScheme.PRE_REGISTERED.value -> PreRegisteredSchemeAuthorizationRequestHandler(
            trustedVerifiers,
            authorizationRequestParameters,
            shouldValidateClient,
            setResponseUri
        )

        ClientIdScheme.REDIRECT_URI.value -> RedirectUriSchemeAuthorizationRequestHandler(
            authorizationRequestParameters,
            setResponseUri
        )

        ClientIdScheme.DID.value -> DidSchemeAuthorizationRequestHandler(
            authorizationRequestParameters,
            setResponseUri
        )

        else -> throw Logger.handleException(
            exceptionType = "InvalidClientIdScheme",
            className = className,
            message = "Given client_id_scheme is not supported"
        )
    }
}

fun validateAttribute(
    authorizationRequestParameters: Map<String, Any>,
    attribute: String,
) {
    val value = getStringValue(authorizationRequestParameters, attribute)
    if (value == null || value == "null" || value.isEmpty()) {
        throw Logger.handleException(
            exceptionType = if (authorizationRequestParameters[attribute] == null) "MissingInput" else "InvalidInput",
            fieldPath = listOf(attribute),
            className = className,
            fieldType = "String"
        )
    }
}

fun extractQueryParameters(query: String): MutableMap<String, Any> {
    try {
        val urlDecodedQueryString = URLDecoder.decode(query, StandardCharsets.UTF_8.toString())
        return urlDecodedQueryString.split("&").map { it.split("=") }
            .associateByTo(mutableMapOf(), { it[0] }, { it[1] })
    } catch (exception: Exception) {
        throw Logger.handleException(
            exceptionType = "InvalidQueryParams",
            message = "Exception occurred when extracting the query params from Authorization Request : ${exception.message}",
            className = className
        )
    }
}

fun parseAndValidatePresentationDefinition(authorizationRequestParameters: MutableMap<String, Any>) {
    val hasPresentationDefinition =
        authorizationRequestParameters.containsKey(PRESENTATION_DEFINITION.value)
    val hasPresentationDefinitionUri =
        authorizationRequestParameters.containsKey(PRESENTATION_DEFINITION_URI.value)
    var presentationDefinition : Any

    when {
        hasPresentationDefinition && hasPresentationDefinitionUri -> {
            throw Logger.handleException(
                exceptionType = "InvalidQueryParams",
                message = "Either presentation_definition or presentation_definition_uri request param can be provided but not both",
                className = className
            )
        }

        hasPresentationDefinition -> {
            validateAttribute(authorizationRequestParameters, PRESENTATION_DEFINITION.value)
            presentationDefinition = authorizationRequestParameters[PRESENTATION_DEFINITION.value]!!
        }

        hasPresentationDefinitionUri -> {
            validateAttribute(authorizationRequestParameters, PRESENTATION_DEFINITION_URI.value)
            val presentationDefinitionUri = getStringValue(
                authorizationRequestParameters,
                PRESENTATION_DEFINITION_URI.value
            )!!
            if (!isValidUrl(presentationDefinitionUri)) {
                throw Logger.handleException(
                    exceptionType = "InvalidData",
                    className = className,
                    message = "${PRESENTATION_DEFINITION_URI.value} data is not valid"
                )
            }
            val response =
                sendHTTPRequest(
                    url = presentationDefinitionUri,
                    method = HTTP_METHOD.GET
                )
            presentationDefinition = response["body"].toString()
        }
        else -> {
            throw Logger.handleException(
                exceptionType = "InvalidQueryParams",
                message = "Either presentation_definition or presentation_definition_uri request param must be present",
                className = className
            )
        }
    }

    val presentationDefinitionObj = when (presentationDefinition) {
        is String -> deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
        is Map<*, *> -> deserializeAndValidate (presentationDefinition as Map<String, Any>, PresentationDefinitionSerializer)
        else -> null
    }
    authorizationRequestParameters[PRESENTATION_DEFINITION.value] = presentationDefinitionObj !!
}

fun parseAndValidateClientMetadata(authorizationRequestParameters: MutableMap<String, Any>) {
    authorizationRequestParameters[CLIENT_METADATA.value]?.let {
        val clientMetadata = when (it) {
            is String -> deserializeAndValidate(it, ClientMetadataSerializer)
            is Map<*, *> -> deserializeAndValidate(it as Map<String, Any>, ClientMetadataSerializer)
            else -> null
        }
        authorizationRequestParameters[CLIENT_METADATA.value] = clientMetadata !!
    }
}

fun validateAuthorizationRequestObjectAndParameters(
    params: Map<String, Any>,
    authorizationRequestObject: Map<String, Any>,
) {
    if (params[CLIENT_ID.value] != authorizationRequestObject[CLIENT_ID.value]) {
        throw Logger.handleException(
            exceptionType = "InvalidData",
            message = "Client Id mismatch in Authorization Request parameter and the Request Object",
            className = className
        )

    }
    if (params[CLIENT_ID_SCHEME.value] != null && params[CLIENT_ID_SCHEME.value] != authorizationRequestObject[CLIENT_ID_SCHEME.value]) {
        throw Logger.handleException(
            exceptionType = "InvalidData",
            message = "Client Id Scheme mismatch in Authorization Request parameter and the Request Object",
            className = className
        )
    }
}

fun extractClientIdScheme(clientId: String): String {
    val components = clientId.split(":", limit = 2)

    return if (components.size > 1) {
        components[0]
    } else {
        // Fallback client_id_scheme pre-registered; pre-registered clients MUST NOT contain a : character in their Client Identifier
        ClientIdScheme.PRE_REGISTERED.value
    }
}


fun extractClientIdentifier(clientId: String): String {
    val components = clientId.split(":", limit = 2)
    return if (components.size > 1) {
        val clientIdScheme = components[0]
        // DID client ID scheme will have the client id itself with did prefix, example - did:example:123#1. So there will not be additional prefix stating client_id_scheme
        if (clientIdScheme == ClientIdScheme.DID.value) {
            clientId
        } else {
            components[1]
        }
    } else {
        // client_id_scheme is optional (Fallback client_id_scheme - pre-registered) i.e., a : character is not present in the Client Identifier
        clientId
    }
}