package io.mosip.openID4VP.authorizationResponse.vpToken

import io.mosip.openID4VP.authorizationResponse.models.vpToken.CredentialFormatSpecificVPToken
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement

@Serializable(VPTokenTypeSerializer::class)
sealed class VPTokenType {
    @Serializable
    @SerialName("VPTokenArray")
    data class VPTokenArray(val value: List<CredentialFormatSpecificVPToken>) : VPTokenType()

    @Serializable
    @SerialName("VPToken")
    data class VPToken(val value: CredentialFormatSpecificVPToken) : VPTokenType()
}

object VPTokenTypeSerializer : KSerializer<VPTokenType> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("ShapeType")

    override fun serialize(encoder: Encoder, value: VPTokenType) {
        val jsonEncoder = encoder as? JsonEncoder ?: error("This serializer only works with JSON")
        val jsonElement = when (value) {
            is VPTokenType.VPToken -> Json.encodeToJsonElement(value.value)
            is VPTokenType.VPTokenArray -> Json.encodeToJsonElement(value.value)
        }
        jsonEncoder.encodeJsonElement(jsonElement)
    }

    override fun deserialize(decoder: Decoder): VPTokenType {
        val jsonDecoder = decoder as? JsonDecoder ?: error("This serializer only works with JSON")
        val jsonElement = jsonDecoder.decodeJsonElement()

        return when (jsonElement) {
            is JsonArray -> VPTokenType.VPTokenArray(Json.decodeFromJsonElement(jsonElement))
            is JsonObject -> VPTokenType.VPToken(Json.decodeFromJsonElement(jsonElement))
            else -> error("Invalid ShapeType format")
        }
    }
}