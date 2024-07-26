package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import io.mosip.openID4VP.authorizationRequest.presentationDefinition.credentialFormatTypes.Format
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import kotlinx.serialization.*
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder

@Serializable
class PresentationDefinition (
    val id: String,
    @SerialName("input_descriptors") val inputDescriptors: List<InputDescriptor>,
    val name: String?,
    val purpose: String?,
    val format: Format? ) {

    companion object Serializer : DeserializationStrategy<PresentationDefinition> {
        override val descriptor: SerialDescriptor = buildClassSerialDescriptor("PresentationDefinition") {
            element<String>("id")
            element<ArrayList<InputDescriptor>>("input_descriptors")
            element<String>("name", isOptional = true)
            element<String>("purpose", isOptional = true)
            element<Format>("format", isOptional = true)
        }

        override fun deserialize(decoder: Decoder): PresentationDefinition {
            val builtInDecoder = decoder.beginStructure(descriptor)
            var id: String? = null
            var inputDescriptors: List<InputDescriptor>? = null
            var name: String? = null
            var purpose: String? = null
            var format: Format? = null

            loop@ while (true) {
                when (builtInDecoder.decodeElementIndex(descriptor)) {
                    CompositeDecoder.DECODE_DONE -> break@loop
                    0 -> id = builtInDecoder.decodeStringElement(descriptor, 0)
                    1 -> inputDescriptors = builtInDecoder.decodeSerializableElement(descriptor, 1, ListSerializer(InputDescriptor.serializer()))
                    2 -> name = builtInDecoder.decodeStringElement(descriptor, 2)
                    3 -> purpose = builtInDecoder.decodeStringElement(descriptor, 3)
                    4 -> format = builtInDecoder.decodeSerializableElement(descriptor, 4, Format.serializer())
                }
            }

            builtInDecoder.endStructure(descriptor)

            requireNotNull(id) { throw AuthorizationRequestExceptions.MissingInput("presentation_definition : id") }
            requireNotNull(inputDescriptors) { throw AuthorizationRequestExceptions.MissingInput("presentation_definition : input_descriptors") }

            return PresentationDefinition(
                id = id,
                inputDescriptors = inputDescriptors,
                name = name,
                purpose = purpose,
                format = format
            )
        }
    }

    fun validate() {
        try {
            require(id.isNotEmpty()) {
                throw AuthorizationRequestExceptions.InvalidInput("presentation_Definition : id")
            }
            require(inputDescriptors.isNotEmpty()) { throw AuthorizationRequestExceptions.InvalidInput("presentation_definition : input_descriptors")}

            inputDescriptors.forEachIndexed{index, inputDescriptor -> inputDescriptor.validate(index)}

            format?.validate()
        }catch (e: AuthorizationRequestExceptions.InvalidInput){
            throw e
        }
    }
}

