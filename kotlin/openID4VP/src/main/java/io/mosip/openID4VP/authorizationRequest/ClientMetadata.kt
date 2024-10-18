package io.mosip.openID4VP.authorizationRequest

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

private val className = ClientMetadata::class.simpleName!!

object ClientMetadataSerializer : KSerializer<ClientMetadata> {
	override val descriptor: SerialDescriptor = buildClassSerialDescriptor("ClientMetadata") {
		element<String>("name")
	}

	override fun deserialize(decoder: Decoder): ClientMetadata {
		val builtInDecoder = decoder.beginStructure(descriptor)
		var name: String? = null

		loop@ while (true) {
			when (builtInDecoder.decodeElementIndex(descriptor)) {
				CompositeDecoder.DECODE_DONE -> break@loop
				0 -> name = builtInDecoder.decodeStringElement(descriptor, 0)
			}
		}

		builtInDecoder.endStructure(descriptor)

		requireNotNull(name) {
			throw Logger.handleException("MissingInput", "client_metadata", "name", className)
		}
		return ClientMetadata(name = name)
	}

	@Generated
	override fun serialize(encoder: Encoder, value: ClientMetadata) {
		val builtInEncoder = encoder.beginStructure(descriptor)
		builtInEncoder.encodeStringElement(descriptor, 0, value.name)
		builtInEncoder.endStructure(descriptor)
	}
}

@Serializable(with = ClientMetadataSerializer::class)
class ClientMetadata(val name: String) : Validatable {
	override fun validate() {
		try {
			require(name.isNotEmpty()) {
				throw Logger.handleException("InvalidInput", "client_metadata", "name", className)
			}
		} catch (exception: Exception) {
			throw exception
		}
	}
}