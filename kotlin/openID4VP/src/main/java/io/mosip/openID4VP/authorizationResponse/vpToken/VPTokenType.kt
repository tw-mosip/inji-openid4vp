package io.mosip.openID4VP.authorizationResponse.vpToken

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.JsonSerializer
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.annotation.JsonSerialize

@JsonSerialize(using = VPTokenTypeSerializer::class)
sealed class VPTokenType {
    data class VPTokenArray(val value: List<VPToken>) : VPTokenType()

    data class VPTokenElement(val value: VPToken) : VPTokenType()
}

class VPTokenTypeSerializer : JsonSerializer<VPTokenType>() {
    override fun serialize(value: VPTokenType, gen: JsonGenerator, serializers: SerializerProvider) {
        when (value) {
            is VPTokenType.VPTokenArray -> gen.writeObject(value.value)
            is VPTokenType.VPTokenElement -> gen.writeObject(value.value)
        }
    }
}
