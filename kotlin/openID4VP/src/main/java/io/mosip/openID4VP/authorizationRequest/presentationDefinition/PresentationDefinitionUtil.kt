package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.PRESENTATION_DEFINITION
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.PRESENTATION_DEFINITION_URI
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.validateAttribute
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.isValidUrl
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest

private val className = PresentationDefinition::class.simpleName!!
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
        else -> throw Logger.handleException(
            exceptionType = "InvalidData",
            message = "presentation_definition must be of type String or Map ",
            className = className
        )
    }
    authorizationRequestParameters[PRESENTATION_DEFINITION.value] = presentationDefinitionObj
}