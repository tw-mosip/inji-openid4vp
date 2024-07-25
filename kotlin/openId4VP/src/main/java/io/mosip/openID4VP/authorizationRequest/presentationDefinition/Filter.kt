package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import io.mosip.openID4VP.exception.AuthorizationRequestExceptions
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder

@Serializable
class Filter(val type: String,val pattern: String) {
    companion object Serializer : DeserializationStrategy<Filter> {
        override val descriptor: SerialDescriptor = buildClassSerialDescriptor("Filter") {
            element<String>("type")
            element<String>("pattern")
        }

        override fun deserialize(decoder: Decoder): Filter {
            val builtInDecoder = decoder.beginStructure(descriptor)
            var type: String? = null
            var pattern: String? = null

            loop@ while (true) {
                when (builtInDecoder.decodeElementIndex(descriptor)) {
                    CompositeDecoder.DECODE_DONE -> break@loop
                    0 -> type = builtInDecoder.decodeStringElement(descriptor, 0)
                    1 -> pattern = builtInDecoder.decodeStringElement(descriptor, 1)
                }
            }

            builtInDecoder.endStructure(descriptor)

            requireNotNull(type) { throw AuthorizationRequestExceptions.MissingInput("filter : type") }
            requireNotNull(pattern) {  throw AuthorizationRequestExceptions.MissingInput("filter : pattern")}

            return Filter(type = type, pattern = pattern)
        }
    }

    fun validate(){
        require(type.isNotEmpty()) { throw AuthorizationRequestExceptions.InvalidInput("filter : type")}
        require(pattern.isNotEmpty()) { throw AuthorizationRequestExceptions.InvalidInput("filter : pattern")}
    }
}