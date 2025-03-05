package io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning

import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.types.LdpVPTokenForSigning
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

@Serializable(VPTokenForSigningSerializer::class)
interface VPTokenForSigning {
    val dataType: String
}

object VPTokenForSigningSerializer : JsonContentPolymorphicSerializer<VPTokenForSigning>(VPTokenForSigning::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<VPTokenForSigning> {
        return when (val dataType = element.jsonObject["dataType"]?.jsonPrimitive?.content) {
            "LdpVPTokenForSigning" -> LdpVPTokenForSigning.serializer()
            else -> throw Exception("Unknown VPTokenForSigning: key '${dataType}' not found or does not matches any VPTokenForSigning type")
        }
    }
}