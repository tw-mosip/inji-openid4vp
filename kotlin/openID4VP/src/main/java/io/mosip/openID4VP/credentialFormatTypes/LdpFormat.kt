package io.mosip.openID4VP.credentialFormatTypes

import Generated
import io.mosip.openID4VP.authorizationRequest.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.common.Logger
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

private val className = LdpFormat::class.simpleName!!
object LdpFormatSerializer : KSerializer<LdpFormat> {
	override val descriptor: SerialDescriptor = buildClassSerialDescriptor("LdpFormat") {
		element<List<String>>("proof_type")
	}

	override fun deserialize(decoder: Decoder): LdpFormat {
		val builtInDecoder = decoder.beginStructure(descriptor)
		var proofType: List<String>? = null

		loop@ while (true) {
			when (builtInDecoder.decodeElementIndex(descriptor)) {
				CompositeDecoder.DECODE_DONE -> break@loop
				0 -> proofType = builtInDecoder.decodeSerializableElement(
					descriptor, 0, ListSerializer(String.serializer())
				)

				else -> throw SerializationException("Unknown index")
			}
		}

		builtInDecoder.endStructure(descriptor)

		requireNotNull(proofType) {
			throw Logger.handleException(
				exceptionType = "MissingInput",
				fieldPath = listOf("ldpFormat", "proof_type"),
				className = className
			)
		}
		return LdpFormat(proofType = proofType)
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
) {
	fun validate() {
		proofType.ifEmpty { throw AuthorizationRequestExceptions.InvalidInput("LdpFormat : proofType") }
	}
}