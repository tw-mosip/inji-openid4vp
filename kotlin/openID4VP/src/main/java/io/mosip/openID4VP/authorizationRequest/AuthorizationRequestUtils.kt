package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types.*
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.common.ClientIdScheme
import io.mosip.openID4VP.common.ClientIdScheme.PRE_REGISTERED
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.ResponseMode
import io.mosip.openID4VP.common.ResponseMode.DIRECT_POST_JWT
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
    val clientIdScheme = getStringValue(authorizationRequestParameters, CLIENT_ID_SCHEME.value)
        ?: PRE_REGISTERED.value
    return when (clientIdScheme) {
        PRE_REGISTERED.value -> PreRegisteredSchemeAuthorizationRequestHandler(
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



