package io.mosip.openID4VP.credentialFormatTypes

import Generated
import io.mosip.openID4VP.common.FieldDeserializer
import io.mosip.openID4VP.common.Logger
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.jsonObject

private val className = LdpFormat::class.simpleName!!
object LdpFormatSerializer : KSerializer<LdpFormat> {
	override val descriptor: SerialDescriptor = buildClassSerialDescriptor("LdpFormat") {
		element<List<String>>("proof_type")
	}

	override fun deserialize(decoder: Decoder): LdpFormat {
		val jsonDecoder = try {
			decoder as JsonDecoder
		} catch (e: ClassCastException) {
			throw Logger.handleException(
				exceptionType = "DeserializationFailure",
				fieldPath = listOf("ldpFormat"),
				message = e.message!!,
				className = className
			)
		}
		val jsonObject = jsonDecoder.decodeJsonElement().jsonObject
		val deserializer = FieldDeserializer(
			jsonObject = jsonObject, className = className, parentField = "ldpFormat"
		)

		val proofType: List<String>? = deserializer.deserializeField(
			key = "proof_type",
			fieldType = "List<String>",
			deserializer = ListSerializer(String.serializer()),
			isMandatory = true
		)
		return LdpFormat(proofType = proofType!!)
	}

	@Generated
	override fun serialize(encoder: Encoder, value: LdpFormat) {
		val builtInEncoder = encoder.beginStructure(descriptor)

		builtInEncoder.encodeSerializableElement(
			descriptor, 0, ListSerializer(String.serializer()), value.proofType
		)

		builtInEncoder.endStructure(descriptor)
	}
}

@Serializable(with = LdpFormatSerializer::class)
data class LdpFormat(
	@SerialName("proof_type") val proofType: List<String>
)