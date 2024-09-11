package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import Generated
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.common.Logger
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

private val className = PresentationDefinition::class.simpleName!!

object PresentationDefinitionSerializer : KSerializer<PresentationDefinition> {
	override val descriptor: SerialDescriptor =
		buildClassSerialDescriptor("PresentationDefinition") {
			element<String>("id")
			element<ArrayList<InputDescriptor>>("input_descriptors")
			element<String>("name", isOptional = true)
			element<String>("purpose", isOptional = true)
		}

	override fun deserialize(decoder: Decoder): PresentationDefinition {
		val builtInDecoder = decoder.beginStructure(descriptor)
		var id: String? = null
		var inputDescriptors: List<InputDescriptor>? = null
		var name: String? = null
		var purpose: String? = null

		loop@ while (true) {
			when (builtInDecoder.decodeElementIndex(descriptor)) {
				CompositeDecoder.DECODE_DONE -> break@loop
				0 -> id = builtInDecoder.decodeStringElement(descriptor, 0)
				1 -> inputDescriptors = builtInDecoder.decodeSerializableElement(
					descriptor, 1, ListSerializer(InputDescriptor.serializer())
				)

				2 -> name = builtInDecoder.decodeStringElement(descriptor, 2)
				3 -> purpose = builtInDecoder.decodeStringElement(descriptor, 3)
			}
		}

		builtInDecoder.endStructure(descriptor)

		requireNotNull(id) {
			throw Logger.handleException("MissingInput", "presentation_definition", "id", className)
		}
		requireNotNull(inputDescriptors) {
			throw Logger.handleException("MissingInput", "presentation_definition", "input_descriptors", className)
		}

		return PresentationDefinition(
			id = id,
			inputDescriptors = inputDescriptors,
			name = name,
			purpose = purpose,
		)
	}

	@Generated
	override fun serialize(encoder: Encoder, value: PresentationDefinition) {
		val builtInEncoder = encoder.beginStructure(descriptor)
		builtInEncoder.encodeStringElement(descriptor, 0, value.id)
		builtInEncoder.encodeSerializableElement(
			descriptor,
			1,
			ListSerializer(InputDescriptor.serializer()),
			value.inputDescriptors
		)
		value.name?.let { builtInEncoder.encodeStringElement(descriptor, 2, it) }
		value.purpose?.let { builtInEncoder.encodeStringElement(descriptor, 3, it) }
		builtInEncoder.endStructure(descriptor)
	}
}

@Serializable(with = PresentationDefinitionSerializer::class)
class PresentationDefinition(
	val id: String,
	@SerialName("input_descriptors") val inputDescriptors: List<InputDescriptor>,
	val name: String? = null,
	val purpose: String? = null
) {

	fun validate() {
		try {
			require(id.isNotEmpty()) {
				throw Logger.handleException("InvalidInput", "presentation_definition", "id", className)
			}
			require(inputDescriptors.isNotEmpty()) {
				throw Logger.handleException("InvalidInput", "presentation_definition", "input_descriptors", className)
			}

			inputDescriptors.forEach { inputDescriptor ->
				inputDescriptor.validate()
			}
		} catch (exception: AuthorizationRequestExceptions.InvalidInput) {
			throw exception
		}
	}
}

