package io.mosip.openID4VP.authorizationRequest.presentationDefinition.utils

import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import kotlinx.serialization.json.Json

fun validatePresentationDefinition(presentationDefinitionJson: String): PresentationDefinition{
    try {
        val presentationDefinition: PresentationDefinition =
            Json.decodeFromString<PresentationDefinition>(presentationDefinitionJson)

        presentationDefinition.validate()

        return presentationDefinition
    }catch (e: Exception){
        throw e
    }
}