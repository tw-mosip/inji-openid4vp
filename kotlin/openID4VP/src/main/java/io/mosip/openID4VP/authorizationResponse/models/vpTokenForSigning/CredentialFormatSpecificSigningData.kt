package io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning

import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.types.LdpVpSpecificSigningData
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

@Serializable(CredentialFormatSpecificSigningDataSerializer::class)
interface CredentialFormatSpecificSigningData {
    val dataType: String
}

object CredentialFormatSpecificSigningDataSerializer : JsonContentPolymorphicSerializer<CredentialFormatSpecificSigningData>(CredentialFormatSpecificSigningData::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<CredentialFormatSpecificSigningData> {
        return when (val dataType = element.jsonObject["dataType"]?.jsonPrimitive?.content) {
            "LdpVpSpecificSigningData" -> LdpVpSpecificSigningData.serializer()
            else -> throw Exception("Unknown CredentialFormatSpecificSigningData: key '${dataType}' not found or does not matches any CredentialFormatSpecificSigningData type")
        }
    }
}