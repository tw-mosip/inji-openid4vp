package io.mosip.openID4VP.common

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.InputDescriptor
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer.descriptor
import io.mosip.openID4VP.common.Decoder.decodeBase64Data
import io.mosip.openID4VP.jwt.jws.JWSHandler.JwsPart
import io.mosip.openID4VP.constants.HttpMethod
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

private const val URL_PATTERN = "^https://(?:[\\w-]+\\.)+[\\w-]+(?:/[\\w\\-.~!$&'()*+,;=:@%]+)*/?(?:\\?[^#\\s]*)?(?:#.*)?$"

fun isValidUrl(url : String): Boolean {
    return url.matches(URL_PATTERN.toRegex())
}

fun convertJsonToMap(jsonString: String): MutableMap<String, Any> {
    val mapper = jacksonObjectMapper()
    return mapper.readValue(
        jsonString,
        object : TypeReference<MutableMap<String, Any>>() {})
}

fun isJWS(input: String): Boolean {
    return input.split(".").size == 3
}

fun determineHttpMethod(method: String): HttpMethod {
    return when (method.lowercase()) {
        "get" -> HttpMethod.GET
        "post" -> HttpMethod.POST
        else -> throw IllegalArgumentException("Unsupported HTTP method: $method")
    }
}

fun extractDataJsonFromJws(jws: String, part: JwsPart): MutableMap<String, Any> {
    val components = jws.split(".")
    val payload = components[part.number]
    val decodedString = decodeBase64Data(payload)
    return convertJsonToMap(String(decodedString,Charsets.UTF_8))
}

fun getStringValue(params: Map<String, Any>, key: String): String? {
    return params[key]?.toString()
}

fun validate(
    key: String,
    value: String?,
    className: String
) {
    if (value == null || value == "null" || value.isEmpty()) {
        throw Logger.handleException(
            exceptionType = if (value == null) "MissingInput" else "InvalidInput",
            fieldPath = listOf(key),
            className = className,
            fieldType = "String"
        )
    }
}

inline fun <reified T> encodeToJsonString(data: T, fieldName: String, className: String): String {
    try {
        val objectMapper = jacksonObjectMapper()
        return objectMapper.writeValueAsString(data)
    } catch (exception: Exception) {
        throw Logger.handleException(
            exceptionType = "JsonEncodingFailed",
            message = exception.message,
            fieldPath = listOf(fieldName),
            className = className
        )
    }
}

fun Map<*, *>.toJson(): Map<String, String> {
    val objectMapper = jacksonObjectMapper()

    return this.mapKeys { (key, _) ->
        when (key) {
            is Enum<*> -> {
                key.let {
                    it::class.members.find { member -> member.name == "value" }
                        ?.call(it) as? String ?: it.toString()
                }
            }

            else -> key?.toString() ?: "null"
        }

    }.mapValues { (_, value) ->
        objectMapper.writeValueAsString(value)
    }
}

fun Any.toJsonEncodedMap(): Map<String, String> {
    val objectMapper = jacksonObjectMapper()
    val jsonString = objectMapper.writeValueAsString(this)
    val rawMap = objectMapper.readValue(jsonString, Map::class.java) as Map<String, Any>

    return rawMap
        .filterValues { it != null }
        .mapValues { (_, value) ->
            when (value) {
                is Map<*, *> -> objectMapper.writeValueAsString(value)
                else -> value.toString()
            }
        }
}