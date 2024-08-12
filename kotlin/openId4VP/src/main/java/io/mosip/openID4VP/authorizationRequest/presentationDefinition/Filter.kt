package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import Generated
import io.mosip.openID4VP.common.Logger
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

private val className = Filter::class.simpleName!!

object FilterSerializer : KSerializer<Filter> {
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

		requireNotNull(type) {
			throw Logger.handleException("MissingInput", "filter", "type", className)
		}
		requireNotNull(pattern) {
			throw Logger.handleException("MissingInput", "filter", "pattern", className)
		}

		return Filter(type = type, pattern = pattern)
	}

	@Generated
	override fun serialize(encoder: Encoder, value: Filter) {
		val builtInEncoder = encoder.beginStructure(descriptor)
		builtInEncoder.encodeStringElement(descriptor, 0, value.type)
		builtInEncoder.encodeStringElement(descriptor, 1, value.pattern)
		builtInEncoder.endStructure(descriptor)
	}
}

@Serializable(with = FilterSerializer::class)
class Filter(val type: String, val pattern: String) {
	fun validate() {
		try {
			require(type.isNotEmpty()) {
				throw Logger.handleException("InvalidInput", "filter", "type", className)
			}
			require(pattern.isNotEmpty()) {
				throw Logger.handleException("InvalidInput", "filter", "pattern", className)
			}
		} catch (exception: Exception) {
			throw exception
		}
	}
}