package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import Generated
import io.mosip.openID4VP.common.Logger
import isNeitherNullNorEmpty
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

private val logTag = Logger.getLogTag(Constraints::class.simpleName!!)
private val className = Constraints::class.simpleName!!
object ConstraintsSerializer : KSerializer<Constraints> {
	override val descriptor: SerialDescriptor = buildClassSerialDescriptor("Constraints") {
		element<List<Fields>>("fields", isOptional = true)
		element<String>("limit_disclosure", isOptional = true)
	}

	override fun deserialize(decoder: Decoder): Constraints {
		val builtInDecoder = decoder.beginStructure(descriptor)
		var fields: List<Fields>? = null
		var limitDisclosure: String? = null

		loop@ while (true) {
			when (builtInDecoder.decodeElementIndex(descriptor)) {
				CompositeDecoder.DECODE_DONE -> break@loop
				0 -> fields = builtInDecoder.decodeSerializableElement(
					descriptor, 0, ListSerializer(Fields.serializer())
				)

				1 -> limitDisclosure = builtInDecoder.decodeStringElement(descriptor, 1)
			}
		}

		builtInDecoder.endStructure(descriptor)

		return Constraints(
			fields = fields, limitDisclosure = limitDisclosure
		)
	}

	@Generated
	override fun serialize(encoder: Encoder, value: Constraints) {
		val builtInEncoder = encoder.beginStructure(descriptor)
		value.fields?.let {
			builtInEncoder.encodeSerializableElement(
				descriptor,
				0,
				ListSerializer(Fields.serializer()),
				it
			)
		}
		value.limitDisclosure?.let { builtInEncoder.encodeStringElement(descriptor, 1, it) }
		builtInEncoder.endStructure(descriptor)
	}
}

@Serializable(with = ConstraintsSerializer::class)
class Constraints(
	val fields: List<Fields>? = null,
	@SerialName("limit_disclosure") val limitDisclosure: String? = null
) {
	fun validate() {
		try {
			fields?.forEach { field ->
				field.validate()
			}

			limitDisclosure?.let {
				require(isNeitherNullNorEmpty(limitDisclosure)) {
					throw Logger.handleException(
						exceptionType = "InvalidInput",
						fieldPath = listOf("constraints", "limit_disclosure"),
						className = className
					)
				}

				LimitDisclosure.values().firstOrNull { it.value == limitDisclosure }
					?: throw Logger.handleException(
						exceptionType = "InvalidLimitDisclosure",
						className = className
					)
			}
		} catch (exception: Exception) {
			Logger.error(logTag, exception)
			throw exception
		}
	}
}

