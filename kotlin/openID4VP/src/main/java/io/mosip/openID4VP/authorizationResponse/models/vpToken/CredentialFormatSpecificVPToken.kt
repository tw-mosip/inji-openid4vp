package io.mosip.openID4VP.authorizationResponse.models.vpToken

import io.mosip.openID4VP.authorizationResponse.models.vpToken.types.LdpVPToken
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

@Serializable(CredentialFormatSpecificVPTokenSerializer::class)
interface CredentialFormatSpecificVPToken{
    val dataType: String
}

object CredentialFormatSpecificVPTokenSerializer :
    JsonContentPolymorphicSerializer<CredentialFormatSpecificVPToken>(
        CredentialFormatSpecificVPToken::class
    ) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<CredentialFormatSpecificVPToken> {
        return when (val dataType = element.jsonObject["dataType"]?.jsonPrimitive?.content) {
            "LdpVP" -> LdpVPToken.serializer()
            else -> throw Exception("Unknown CredentialFormatSpecificVPToken: key '${dataType}' not found or does not matches any CredentialFormatSpecificVPToken type")
        }
    }
}