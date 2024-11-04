package io.mosip.openID4VP.credentialFormatTypes

import Generated
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object FormatSerializer : KSerializer<Format> {
	override val descriptor: SerialDescriptor = buildClassSerialDescriptor("Format") {
		element<LdpFormat>("ldp_vc", isOptional = true)
	}

	override fun deserialize(decoder: Decoder): Format {
		val builtInDecoder = decoder.beginStructure(descriptor)
		var ldpVc: LdpFormat? = null

		loop@ while (true) {
			when (builtInDecoder.decodeElementIndex(descriptor)) {
				CompositeDecoder.DECODE_DONE -> break@loop
				0 -> ldpVc =
					builtInDecoder.decodeSerializableElement(descriptor, 0, LdpFormat.serializer())
			}
		}

		builtInDecoder.endStructure(descriptor)

		return Format(
			ldpVc = ldpVc,
		)
	}

	@Generated
	override fun serialize(encoder: Encoder, value: Format) {
		val builtInEncoder = encoder.beginStructure(descriptor)

		value.ldpVc?.let {
			builtInEncoder.encodeSerializableElement(descriptor, 0, LdpFormat.serializer(), it)
		}

		builtInEncoder.endStructure(descriptor)
	}
}

@Serializable(with = FormatSerializer::class)
class Format(
	@SerialName("ldp_vc") val ldpVc: LdpFormat?,
) {
	fun validate() {
		try {
			ldpVc?.validate()
		} catch (e: AuthorizationRequestExceptions.InvalidInput) {
			throw e
		}
	}

}