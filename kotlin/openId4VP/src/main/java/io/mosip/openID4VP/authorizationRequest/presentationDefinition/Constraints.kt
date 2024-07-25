package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import io.mosip.openID4VP.exception.AuthorizationRequestExceptions
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder

@Serializable
class Constraints(
    val fields: List<Field>?,
    @SerialName("limit_disclosure") val limitDisclosure: String?
) {
    companion object Serializer : DeserializationStrategy<Constraints> {
        override val descriptor: SerialDescriptor = buildClassSerialDescriptor("Constraints") {
            element<List<Field>>("fields", isOptional = true)
            element<String>("limit_disclosure", isOptional = true)
        }

        override fun deserialize(decoder: Decoder): Constraints {
            val builtInDecoder = decoder.beginStructure(descriptor)
            var fields: List<Field>? = null
            var limitDisclosure: String? = null

            loop@ while (true) {
                when (builtInDecoder.decodeElementIndex(descriptor)) {
                    CompositeDecoder.DECODE_DONE -> break@loop
                    0 -> fields = builtInDecoder.decodeSerializableElement(descriptor, 0, ListSerializer(Field.serializer()))
                    1 -> limitDisclosure = builtInDecoder.decodeStringElement(descriptor, 1)
                }
            }

            builtInDecoder.endStructure(descriptor)

            return Constraints(
                fields = fields,
                limitDisclosure = limitDisclosure
            )
        }
    }
    
    fun validate() {
        try {
            fields?.forEachIndexed { index, field ->
                field.validate(index)
            }

            LimitDisclosure.values().firstOrNull { it.value == limitDisclosure }
                ?: throw AuthorizationRequestExceptions.InvalidInput("constraints : limit_disclosure")
        }catch (e: AuthorizationRequestExceptions.InvalidInput){
            throw e
        }
    }
}

@Serializable
enum class LimitDisclosure(val value: String) {
    REQUIRED("required"),
    PREFERRED("preferred");
}

