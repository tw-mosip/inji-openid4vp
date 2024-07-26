package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder

@Serializable
class Field(
    val path: List<String>,
    val id: String?,
    val purpose: String?,
    val name: String?,
    val filter: Filter?,
    val optional: Boolean?
) {
    companion object Serializer : DeserializationStrategy<Field> {
        override val descriptor: SerialDescriptor = buildClassSerialDescriptor("Fields") {
            element<List<String>>("path")
            element<String>("id", isOptional = true)
            element<String>("purpose", isOptional = true)
            element<String>("name", isOptional = true)
            element<Filter>("filter", isOptional = true)
            element<Boolean>("optional", isOptional = true)
        }

        override fun deserialize(decoder: Decoder): Field {
            val builtInDecoder = decoder.beginStructure(descriptor)
            var path: List<String>? = null
            var id: String? = null
            var purpose: String? = null
            var name: String? = null
            var filter: Filter? = null
            var optional: Boolean? = null

            loop@ while (true) {
                when (builtInDecoder.decodeElementIndex(descriptor)) {
                    CompositeDecoder.DECODE_DONE -> break@loop
                    0 -> path = builtInDecoder.decodeSerializableElement(descriptor, 0, ListSerializer(String.serializer()))
                    1 -> id = builtInDecoder.decodeStringElement(descriptor, 1)
                    2 -> purpose = builtInDecoder.decodeStringElement(descriptor, 2)
                    3 -> name = builtInDecoder.decodeStringElement(descriptor, 3)
                    4 -> filter = builtInDecoder.decodeSerializableElement(descriptor, 4, Filter.serializer())
                    5 -> optional = builtInDecoder.decodeBooleanElement(descriptor, 5)
                }
            }

            builtInDecoder.endStructure(descriptor)

            requireNotNull(path) { throw AuthorizationRequestExceptions.MissingInput("fields : path") }

            return Field(
                path = path,
                id = id,
                purpose = purpose,
                name = name,
                filter = filter,
                optional = optional
            )
        }
    }
    fun validate(index: Number) {
        try {
            require(path.isNotEmpty()) { throw AuthorizationRequestExceptions.InvalidInput("field - $index : path") }

            filter?.validate()
        }catch (e: Exception){
            throw  e
        }
    }

}