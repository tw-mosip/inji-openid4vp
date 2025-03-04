package io.mosip.openID4VP.authorizationRequest.clientMetadata

import Generated
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.FieldsSerializer
import io.mosip.openID4VP.common.FieldDeserializer
import io.mosip.openID4VP.common.Logger
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.jsonObject


private val className = Jwk::class.simpleName!!

object JwkSerializer : KSerializer<Jwk> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("Jwk") {
        element<String>("kty", isOptional = false)
        element<String>("use", isOptional = false)
        element<String>("crv", isOptional = false)
        element<String>("x", isOptional = false)
        element<String>("alg", isOptional = false)
        element<String>("kid", isOptional = false)
        element<String>("y", isOptional = true)
    }

    override fun deserialize(decoder: Decoder): Jwk {
        val jsonDecoder = try {
            decoder as JsonDecoder
        } catch (e: ClassCastException) {
            throw Logger.handleException(
                exceptionType = "DeserializationFailure",
                fieldPath = listOf("jwk"),
                message = e.message!!,
                className = className
            )
        }

        val jsonObject = jsonDecoder.decodeJsonElement().jsonObject
        val deserializer = FieldDeserializer(
            jsonObject = jsonObject, className = className, parentField = "jwk"
        )

        val kty: String = deserializer.deserializeField(
            key = "kty",
            fieldType = "String",
            isMandatory = true
        )!!
        val use: String = deserializer.deserializeField(
            key = "use",
            fieldType = "String",
            isMandatory = true
        )!!
        val crv: String = deserializer.deserializeField(
            key = "crv",
            fieldType = "String",
            isMandatory = true
        )!!
        val x: String = deserializer.deserializeField(
            key = "x",
            fieldType = "String",
            isMandatory = true
        )!!
        val alg: String = deserializer.deserializeField(
            key = "alg",
            fieldType = "String",
            isMandatory = true
        )!!
        val kid: String = deserializer.deserializeField(
            key = "kid",
            fieldType = "String",
            isMandatory = true
        )!!
        val y: String? = deserializer.deserializeField(
            key = "y",
            fieldType = "String",
        )
        return Jwk(kty = kty, use = use, crv = crv, x = x, alg = alg, kid = kid, y = y)
    }



    @Generated
    override fun serialize(encoder: Encoder, value: Jwk) {
        val builtInEncoder = encoder.beginStructure(FieldsSerializer.descriptor)
        builtInEncoder.encodeStringElement(FieldsSerializer.descriptor, 0, value.kty)
        builtInEncoder.encodeStringElement(FieldsSerializer.descriptor, 1, value.use)
        builtInEncoder.encodeStringElement(FieldsSerializer.descriptor, 2, value.crv)
        builtInEncoder.encodeStringElement(FieldsSerializer.descriptor, 3, value.x)
        builtInEncoder.encodeStringElement(FieldsSerializer.descriptor, 4, value.alg)
        builtInEncoder.encodeStringElement(FieldsSerializer.descriptor, 5, value.kid)
        value.y?.let { builtInEncoder.encodeStringElement(FieldsSerializer.descriptor, 6, it) }
        builtInEncoder.endStructure(FieldsSerializer.descriptor)
    }
}

@Serializable(with = JwkSerializer::class)
data class Jwk(
    val kty: String,
    val use: String,
    val crv: String,
    val x: String,
    val alg: String,
    val kid: String,
    val y: String? = null
)