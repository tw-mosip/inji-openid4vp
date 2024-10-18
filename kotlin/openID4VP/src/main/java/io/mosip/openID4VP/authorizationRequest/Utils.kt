package io.mosip.openID4VP.authorizationRequest

import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json

interface Validatable {
    fun validate()
}

fun <T : Validatable> deserializeAndValidate(
    paramJsonAsString: String, type: KSerializer<T>
): T {
    try {
        val deserializedValue: T = Json.decodeFromString(type, paramJsonAsString)
        deserializedValue.validate()

        return deserializedValue
    } catch (exception: Exception) {
        throw exception
    }
}