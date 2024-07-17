package io.mosip.openID4VP.utils

import com.google.gson.Gson
import io.mosip.openID4VP.models.PresentationDefinition

class Deserializer {
    fun deserializeJsonIntoClassInstance(jsonString: String): PresentationDefinition {
        val gson = Gson()

        return gson.fromJson(jsonString, PresentationDefinition::class.java)
    }
}