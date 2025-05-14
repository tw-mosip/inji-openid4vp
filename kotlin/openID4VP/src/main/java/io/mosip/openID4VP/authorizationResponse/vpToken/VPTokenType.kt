package io.mosip.openID4VP.authorizationResponse.vpToken

import com.google.gson.JsonElement
import com.google.gson.JsonSerializationContext
import com.google.gson.JsonSerializer
import java.lang.reflect.Type

sealed class VPTokenType {
    data class VPTokenArray(val value: List<VPToken>) : VPTokenType()

    data class VPTokenElement(val value: VPToken) : VPTokenType()
}

class VPTokenTypeSerializer : JsonSerializer<VPTokenType> {
    override fun serialize(src: VPTokenType, typeOfSrc: Type, context: JsonSerializationContext): JsonElement {
        return when (src) {
            is VPTokenType.VPTokenArray -> context.serialize(src.value)
            is VPTokenType.VPTokenElement -> context.serialize(src.value)
        }
    }
}
