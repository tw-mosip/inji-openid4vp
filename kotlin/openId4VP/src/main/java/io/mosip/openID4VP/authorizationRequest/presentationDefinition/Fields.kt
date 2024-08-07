package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.common.Logger
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
class Fields(
    val path: List<String>,
    val id: String? = null,
    val purpose: String? = null,
    val name: String? = null,
    val filter: Filter? = null,
    val optional: Boolean? = null
) {
    companion object Serializer : DeserializationStrategy<Fields> {
        private val logTag = Logger.getLogTag(this::class.simpleName!!)

        override val descriptor: SerialDescriptor = buildClassSerialDescriptor("Fields") {
            element<List<String>>("path")
            element<String>("id", isOptional = true)
            element<String>("purpose", isOptional = true)
            element<String>("name", isOptional = true)
            element<Filter>("filter", isOptional = true)
            element<Boolean>("optional", isOptional = true)
        }

        override fun deserialize(decoder: Decoder): Fields {
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
                    0 -> path = builtInDecoder.decodeSerializableElement(
                        descriptor, 0, ListSerializer(String.serializer())
                    )

                    1 -> id = builtInDecoder.decodeStringElement(descriptor, 1)
                    2 -> purpose = builtInDecoder.decodeStringElement(descriptor, 2)
                    3 -> name = builtInDecoder.decodeStringElement(descriptor, 3)
                    4 -> filter =
                        builtInDecoder.decodeSerializableElement(descriptor, 4, Filter.serializer())

                    5 -> optional = builtInDecoder.decodeBooleanElement(descriptor, 5)
                }
            }

            builtInDecoder.endStructure(descriptor)

            requireNotNull(path) { throw AuthorizationRequestExceptions.MissingInput("fields : path") }

            return Fields(
                path = path,
                id = id,
                purpose = purpose,
                name = name,
                filter = filter,
                optional = optional
            )
        }
    }

    fun validate(fieldIndex: Number) {
        try {
            require(path.isNotEmpty()) { throw AuthorizationRequestExceptions.InvalidInput("field - $fieldIndex : path") }

            val pathPrefixes = listOf("$.", "$[")
            path.forEachIndexed { pathIndex, p ->
                val isNotValidPrefix = !(pathPrefixes.any { p.startsWith(it) })
                if (isNotValidPrefix) {
                    throw AuthorizationRequestExceptions.InvalidInputPattern("field - $fieldIndex : path - $pathIndex")
                }
            }

            filter?.validate()
        } catch (exception: Exception) {
            Logger.error(logTag, exception)
            throw exception
        }
    }

}