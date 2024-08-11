package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import Generated
import io.mosip.openID4VP.common.Logger
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

private val className = Fields::class.simpleName!!

object FieldsSerializer : KSerializer<Fields> {
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

		requireNotNull(path) {
			Logger.handleException("MissingInput", "fields", "path", className)
		}

		return Fields(
			path = path,
			id = id,
			purpose = purpose,
			name = name,
			filter = filter,
			optional = optional
		)
	}

	@Generated
	override fun serialize(encoder: Encoder, value: Fields) {
		val builtInEncoder = encoder.beginStructure(descriptor)
		builtInEncoder.encodeSerializableElement(
			descriptor,
			0,
			ListSerializer(String.serializer()),
			value.path
		)
		value.id?.let { builtInEncoder.encodeStringElement(descriptor, 1, it) }
		value.purpose?.let { builtInEncoder.encodeStringElement(descriptor, 2, it) }
		value.name?.let { builtInEncoder.encodeStringElement(descriptor, 3, it) }
		value.filter?.let {
			builtInEncoder.encodeSerializableElement(
				descriptor,
				4,
				Filter.serializer(),
				it
			)
		}
		value.optional?.let { builtInEncoder.encodeBooleanElement(descriptor, 5, it) }
		builtInEncoder.endStructure(descriptor)
	}
}

@Serializable(with = FieldsSerializer::class)
class Fields(
	val path: List<String>,
	val id: String? = null,
	val purpose: String? = null,
	val name: String? = null,
	val filter: Filter? = null,
	val optional: Boolean? = null
) {
	fun validate() {
		try {
			require(path.isNotEmpty()) {
				Logger.handleException("InvalidInput", "fields", "path", className)
			}

			val pathPrefixes = listOf("$.", "$[")
			path.forEach { p ->
				val isNotValidPrefix = !(pathPrefixes.any { p.startsWith(it) })
				if (isNotValidPrefix) {
					Logger.handleException(
						"InvalidInputPattern", "fields", "path",
						className
					)
				}
			}

			filter?.validate()
		} catch (exception: Exception) {
			throw exception
		}
	}

}