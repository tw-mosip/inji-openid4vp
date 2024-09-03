package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import kotlinx.serialization.json.Json

fun validatePresentationDefinition(presentationDefinitionJson: String): PresentationDefinition {
    try {
        val presentationDefinition: PresentationDefinition =
            Json.decodeFromString<PresentationDefinition>(presentationDefinitionJson)

        presentationDefinition.validate()

        return presentationDefinition
    } catch (exception: Exception) {
        throw exception
    }
}