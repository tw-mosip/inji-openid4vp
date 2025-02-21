package io.mosip.openID4VP.common

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.mosip.openID4VP.common.Decoder.decodeBase64Data
import io.mosip.openID4VP.jwt.JwtHandler
import io.mosip.openID4VP.networkManager.HTTP_METHOD

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

fun isJWT(authorizationRequest: String): Boolean {
    return authorizationRequest.split(".").size == 3
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


