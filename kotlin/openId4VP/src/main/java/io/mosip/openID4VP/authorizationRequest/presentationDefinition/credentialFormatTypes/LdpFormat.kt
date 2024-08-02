package io.mosip.openID4VP.authorizationRequest.presentationDefinition.credentialFormatTypes

import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import kotlinx.serialization.DeserializationStrategy
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

@Serializable
data class LdpFormat(
    @SerialName("proof_type")
    val proofType: List<String>){

    companion object Serializer : DeserializationStrategy<LdpFormat> {
        override val descriptor: SerialDescriptor = buildClassSerialDescriptor("LdpFormat") {
            element<List<String>>("proofType")
        }

        override fun deserialize(decoder: Decoder): LdpFormat {
            val builtInDecoder = decoder.beginStructure(descriptor)
            var proofType: List<String>? = null

            loop@ while (true) {
                when (builtInDecoder.decodeElementIndex(descriptor)) {
                    CompositeDecoder.DECODE_DONE -> break@loop
                    0 -> proofType = builtInDecoder.decodeSerializableElement(descriptor, 0, ListSerializer(String.serializer()))
                    else -> throw SerializationException("Unknown index")
                }
            }

            builtInDecoder.endStructure(descriptor)

            requireNotNull(proofType) {throw AuthorizationRequestExceptions.MissingInput("LdpFormat : proofType") }

            return LdpFormat(proofType = proofType)
        }
    }
    fun validate(){
        proofType.ifEmpty{ throw AuthorizationRequestExceptions.InvalidInput("LdpFormat : proofType") }
    }
}
