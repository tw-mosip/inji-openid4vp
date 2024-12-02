package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import Generated
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.common.FieldDeserializer
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.credentialFormatTypes.Format
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.jsonObject

private val className = InputDescriptor::class.simpleName!!
object InputDescriptorSerializer : KSerializer<InputDescriptor> {
	override val descriptor: SerialDescriptor = buildClassSerialDescriptor("InputDescriptor") {
		element<String>("id")
		element<String>("name", isOptional = true)
		element<String>("purpose", isOptional = true)
		element<Format>("format", isOptional = true)
		element<Constraints>("constraints")
	}

	override fun deserialize(decoder: Decoder): InputDescriptor {
		val jsonDecoder = try {
			decoder as JsonDecoder
		} catch (e: ClassCastException) {
			throw Logger.handleException(
				exceptionType = "DeserializationFailure",
				fieldPath = listOf("input_descriptor"),
				message = e.message!!,
				className = className
			)
		}
		val jsonObject = jsonDecoder.decodeJsonElement().jsonObject
		val deserializer = FieldDeserializer(
			jsonObject = jsonObject,
			className = className,
			parentField = "input_descriptor"
		)

		val id: String? =
			deserializer.deserializeField(key = "id", fieldType = "String", isMandatory = true)
		val name: String? =
			deserializer.deserializeField(key = "name", fieldType = "String")
		val purpose: String? =
			deserializer.deserializeField(key = "purpose", fieldType = "String")
		val format: Format? =
			deserializer.deserializeField(
				key = "format",
				fieldType = "Format",
				deserializer = Format.serializer()
			)
		val constraints: Constraints? =
			deserializer.deserializeField(
				key = "constraints",
				fieldType = "Constraints",
				deserializer = Constraints.serializer(),
				isMandatory = true
			)

		return InputDescriptor(
			id = id!!,
			name = name,
			purpose = purpose,
			format = format,
			constraints = constraints!!
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
			constraints.validate()
		} catch (exception: AuthorizationRequestExceptions.InvalidInput) {
			throw exception
		}
	}
}
