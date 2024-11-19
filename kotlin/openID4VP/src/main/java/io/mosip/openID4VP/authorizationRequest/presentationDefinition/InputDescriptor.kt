package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import Generated
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.credentialFormatTypes.Format
import isNeitherNullNorEmpty
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

		loop@ while (true) {
			when (builtInDecoder.decodeElementIndex(descriptor)) {
				CompositeDecoder.DECODE_DONE -> break@loop
				0 -> id = builtInDecoder.decodeStringElement(descriptor, 0)
				1 -> name = builtInDecoder.decodeStringElement(descriptor, 1)
				2 -> purpose = builtInDecoder.decodeStringElement(descriptor, 2)
				3 -> format = builtInDecoder.decodeSerializableElement(descriptor, 3, Format.serializer())
				4 -> constraints = builtInDecoder.decodeSerializableElement(
					descriptor, 4, Constraints.serializer()
				)
			}
		}

		builtInDecoder.endStructure(descriptor)

		requireNotNull(id) {
			throw Logger.handleException(
				exceptionType = "MissingInput",
				fieldPath = listOf("input_descriptor", "id"),
				className = className
			)
		}
		requireNotNull(constraints) {
			throw Logger.handleException(
				exceptionType = "MissingInput",
				fieldPath = listOf("input_descriptor", "constraints"),
				className = className
			)
		}

		return InputDescriptor(
			id = id, name = name, purpose = purpose, format = format, constraints = constraints
		)
	}

	@Generated
	override fun serialize(encoder: Encoder, value: InputDescriptor) {
		val builtInEncoder = encoder.beginStructure(descriptor)
		builtInEncoder.encodeStringElement(descriptor, 0, value.id)
		value.name?.let { builtInEncoder.encodeStringElement(descriptor, 1, it) }
		value.purpose?.let { builtInEncoder.encodeStringElement(descriptor, 2, it) }
		builtInEncoder.encodeSerializableElement(
			descriptor, 3, Constraints.serializer(), value.constraints
		)
		builtInEncoder.encodeSerializableElement(
			descriptor, 4, Constraints.serializer(), value.constraints
		)
		builtInEncoder.endStructure(descriptor)
	}
}

@Serializable(with = InputDescriptorSerializer::class)
class InputDescriptor(
	val id: String,
	val name: String? = null,
	val purpose: String? = null,
	val format: Format? = null,
	val constraints: Constraints
) {
	fun validate() {
		try {
			require(isNeitherNullNorEmpty(id)) {
				throw Logger.handleException(
					exceptionType = "InvalidInput",
					fieldPath = listOf("input_descriptor", "id"),
					className = className
				)
			}
			format?.validate()
			constraints.validate()
		} catch (exception: AuthorizationRequestExceptions.InvalidInput) {
			throw exception
		}
	}
}
