package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.common.Logger
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Encoder

private val className = InputDescriptor::class.simpleName!!

object InputDescriptorSerializer : KSerializer<InputDescriptor> {
	override val descriptor: SerialDescriptor = buildClassSerialDescriptor("InputDescriptor") {
		element<String>("id")
		element<String>("name", isOptional = true)
		element<String>("purpose", isOptional = true)
		element<Constraints>("constraints")
	}

	override fun deserialize(decoder: kotlinx.serialization.encoding.Decoder): InputDescriptor {
		val builtInDecoder = decoder.beginStructure(descriptor)
		var id: String? = null
		var name: String? = null
		var purpose: String? = null
		var constraints: Constraints? = null

		loop@ while (true) {
			when (builtInDecoder.decodeElementIndex(descriptor)) {
				CompositeDecoder.DECODE_DONE -> break@loop
				0 -> id = builtInDecoder.decodeStringElement(descriptor, 0)
				1 -> name = builtInDecoder.decodeStringElement(descriptor, 1)
				2 -> purpose = builtInDecoder.decodeStringElement(descriptor, 2)
				3 -> constraints = builtInDecoder.decodeSerializableElement(
					descriptor, 3, Constraints.serializer()
				)
			}
		}

		builtInDecoder.endStructure(descriptor)

		requireNotNull(id) {
			Logger.handleException("MissingInput", "input_descriptor", "id", className)
		}
		requireNotNull(constraints) {
			Logger.handleException("MissingInput", "input_descriptor", "constraints", className)
		}

		return InputDescriptor(
			id = id, name = name, purpose = purpose, constraints = constraints
		)
	}

	override fun serialize(encoder: Encoder, value: InputDescriptor) {
		val builtInEncoder = encoder.beginStructure(descriptor)
		builtInEncoder.encodeStringElement(descriptor, 0, value.id)
		value.name?.let { builtInEncoder.encodeStringElement(descriptor, 1, it) }
		value.purpose?.let { builtInEncoder.encodeStringElement(descriptor, 2, it) }
		builtInEncoder.encodeSerializableElement(
			descriptor, 3, Constraints.serializer(), value.constraints
		)
		builtInEncoder.endStructure(descriptor)
	}
}

@Serializable(with = InputDescriptorSerializer::class)
class InputDescriptor(
	val id: String,
	val name: String? = null,
	val purpose: String? = null,
	val constraints: Constraints
) {
	fun validate(index: Number) {
		try {
			require(id.isNotEmpty()) {
				Logger.handleException("InvalidInput", "input_descriptor - $index", "id", className)
			}

			constraints.validate()
		} catch (exception: AuthorizationRequestExceptions.InvalidInput) {
			throw exception
		}
	}
}
