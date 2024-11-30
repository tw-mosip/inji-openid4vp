package io.mosip.openID4VP.authorizationRequest

import FieldDeserializer
import Generated
import io.mosip.openID4VP.common.Logger
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.jsonObject

private val className = ClientMetadata::class.simpleName!!

object ClientMetadataSerializer : KSerializer<ClientMetadata> {
	override val descriptor: SerialDescriptor = buildClassSerialDescriptor("ClientMetadata") {
		element<String>("name")
		element<String>("logo_url", isOptional = true)
	}

	override fun deserialize(decoder: Decoder): ClientMetadata {
		val jsonDecoder = try {
			decoder as JsonDecoder
		} catch (e: ClassCastException) {
			throw Logger.handleException(
				exceptionType = "DeserializationFailure",
				fieldPath = listOf("client_metadata"),
				message = e.message!!,
				className = className
			)
		}
		val jsonObject = jsonDecoder.decodeJsonElement().jsonObject
		val deserializer = FieldDeserializer(
			jsonObject = jsonObject,
			className = className,
			parentField = "client_metadata"
		)

		val name: String? =
			deserializer.deserializeField(key = "name", fieldType = "String", isMandatory = true)
		val logoUrl: String? =
			deserializer.deserializeField(key = "logo_url", fieldType = "String")

		return ClientMetadata(name = name!!, logoUrl = logoUrl)
	}

	@Generated
	override fun serialize(encoder: Encoder, value: ClientMetadata) {
		val builtInEncoder = encoder.beginStructure(descriptor)
		builtInEncoder.encodeStringElement(descriptor, 0, value.name)
		value.logoUrl?.let { builtInEncoder.encodeStringElement(descriptor, 1, it) }
		builtInEncoder.endStructure(descriptor)
	}
}

@Serializable(with = ClientMetadataSerializer::class)
class ClientMetadata(val name: String, @SerialName("logo_url") val logoUrl: String?) :
	Validatable {
	override fun validate() {
	}
}