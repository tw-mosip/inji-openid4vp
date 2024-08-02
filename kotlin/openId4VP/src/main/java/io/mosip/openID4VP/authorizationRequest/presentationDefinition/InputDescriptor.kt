package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import io.mosip.openID4VP.authorizationRequest.presentationDefinition.credentialFormatTypes.Format
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.CompositeDecoder

@Serializable
class InputDescriptor (
    val id: String,
    val name:String? = null,
    val purpose: String? = null,
    val format: Format? = null,
    val constraints: Constraints)
{

    companion object Serializer: DeserializationStrategy<InputDescriptor>{

        override val descriptor: SerialDescriptor = buildClassSerialDescriptor("InputDescriptor"){
            element<String>("id")
            element<String>("name", isOptional = true)
            element<String>("purpose", isOptional = true)
            element<Format>("format", isOptional = true)
            element<Constraints>("constraints")

        }
        override fun deserialize(decoder: kotlinx.serialization.encoding.Decoder): InputDescriptor {
            val builtInDecoder = decoder.beginStructure(descriptor)
            var id: String? = null
            var name: String? = null
            var purpose: String? = null
            var format: Format? = null
            var constraints: Constraints? = null

            loop@while(true){
                when(builtInDecoder.decodeElementIndex(descriptor)){
                    CompositeDecoder.DECODE_DONE -> break@loop
                    0 -> id = builtInDecoder.decodeStringElement(descriptor,0)
                    1 -> name = builtInDecoder.decodeStringElement(descriptor,1)
                    2 -> purpose = builtInDecoder.decodeStringElement(descriptor,2)
                    3 -> format = builtInDecoder.decodeSerializableElement(descriptor, 3, Format.serializer())
                    4 -> constraints = builtInDecoder.decodeSerializableElement(descriptor, 4, Constraints.serializer())
                }
            }

            builtInDecoder.endStructure(descriptor)

            requireNotNull(id) {throw AuthorizationRequestExceptions.MissingInput("input_descriptor : id")}
            requireNotNull(constraints) {throw AuthorizationRequestExceptions.MissingInput("input_descriptor : constraints")}

            return InputDescriptor(
                id = id,
                name = name,
                purpose = purpose,
                format = format,
                constraints = constraints
            )
        }
    }
    fun validate(index: Number){
        try {
            require(id.isNotEmpty()) {
                throw AuthorizationRequestExceptions.InvalidInput("input_descriptor - $index : id")
            }

            format?.validate()

            constraints.validate()
        }catch (e: AuthorizationRequestExceptions.InvalidInput){
            throw e
        }
    }
}
