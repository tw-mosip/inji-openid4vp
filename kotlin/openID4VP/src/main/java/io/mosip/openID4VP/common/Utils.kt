package io.mosip.openID4VP.common

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.InputDescriptor
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer.descriptor
import io.mosip.openID4VP.common.Decoder.decodeBase64Data
import io.mosip.openID4VP.jwt.JwtHandler
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.encoding.Encoder

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

fun isJWT(input: String): Boolean {
    return input.split(".").size == 3
}

fun determineHttpMethod(method: String): HTTP_METHOD {
    return when (method.lowercase()) {
        "get" -> HTTP_METHOD.GET
        "post" -> HTTP_METHOD.POST
        else -> throw IllegalArgumentException("Unsupported HTTP method: $method")
    }
}

fun extractDataJsonFromJwt(jwtToken: String, part: JwtHandler.JwtPart): MutableMap<String, Any> {
    val components = jwtToken.split(".")
    val payload = components[part.number]
    val decodedString = decodeBase64Data(payload)
    return convertJsonToMap(String(decodedString,Charsets.UTF_8))
}

fun getStringValue(params: Map<String, Any>, key: String): String? {
    return params[key]?.toString()
}

fun serialize(encoder: Encoder, value: PresentationDefinition) {
    val builtInEncoder = encoder.beginStructure(descriptor)
    builtInEncoder.encodeStringElement(descriptor, 0, value.id)
    builtInEncoder.encodeSerializableElement(
        descriptor,
        1,
        ListSerializer(InputDescriptor.serializer()),
        value.inputDescriptors
    )
    value.name?.let { builtInEncoder.encodeStringElement(descriptor, 2, it) }
    value.purpose?.let { builtInEncoder.encodeStringElement(descriptor, 3, it) }
    builtInEncoder.endStructure(descriptor)
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