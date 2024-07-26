package io.mosip.openID4VP.authorizationRequest.presentationDefinition.credentialFormatTypes

import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder

@Serializable
class Format (
    @SerialName("ldp_vc") val ldpVc: LdpFormat?,
    )
{
    companion object Serializer : DeserializationStrategy<Format> {
        override val descriptor: SerialDescriptor = buildClassSerialDescriptor("Format") {
            element<LdpFormat>("ldp_vc", isOptional = true)
        }

        override fun deserialize(decoder: Decoder): Format {
            val builtInDecoder = decoder.beginStructure(descriptor)
            var ldpVc: LdpFormat? = null

            loop@ while (true) {
                when (builtInDecoder.decodeElementIndex(descriptor)) {
                    CompositeDecoder.DECODE_DONE -> break@loop
                    0 -> ldpVc = builtInDecoder.decodeSerializableElement(descriptor, 0, LdpFormat.serializer())
                }
            }

            builtInDecoder.endStructure(descriptor)

            return Format(
                ldpVc = ldpVc,
            )
        }
    }
    fun validate() {
        try {
            ldpVc?.validate()
        }catch (e: AuthorizationRequestExceptions.InvalidInput){
            throw e
        }
    }

}