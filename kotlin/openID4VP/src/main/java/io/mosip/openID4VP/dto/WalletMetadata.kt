
package io.mosip.openID4VP.dto

import Generated
import io.mosip.openID4VP.authorizationRequest.ClientIdScheme
import io.mosip.openID4VP.authorizationRequest.Validatable
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

private val className = WalletMetadata::class.simpleName!!

object WalletMetadataSerializer : KSerializer<WalletMetadata> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("ClientMetadata") {
        element<String>("presentation_definition_uri_supported", isOptional = true)
        element<String>("vp_formats_supported", isOptional = false)
        element<Map<String, String>>("client_id_schemes_supported", isOptional = true)
    }


    override fun deserialize(decoder: Decoder): WalletMetadata {
        val jsonDecoder = try {
            decoder as JsonDecoder
        } catch (e: ClassCastException) {
            throw Logger.handleException(
                exceptionType = "DeserializationFailure",
                fieldPath = listOf("wallet_metadata"),
                message = e.message!!,
                className = className
            )
        }
        val jsonObject = jsonDecoder.decodeJsonElement().jsonObject
        val deserializer = FieldDeserializer(
            jsonObject = jsonObject,
            className = className,
            parentField = "wallet_metadata"
        )

        val presentationDefinitionURISupported: Boolean? =
            deserializer.deserializeField(
                key = "presentation_definition_uri_supported",
                fieldType = "Boolean"
            )
        val vpFormatsSupported: Map<String, VPFormatSupported> =
            deserializer.deserializeField(key = "vp_formats_supported", fieldType = "Map", isMandatory = true)
                ?: throw Logger.handleException(
                    exceptionType = "InvalidInput",
                    fieldPath = listOf("wallet_metadata", "vp_formats_supported"),
                    className = className,
                    fieldType = "map",
                )
        val clientIdSchemesSupported: List<String>? =
            deserializer.deserializeField(key = "client_id_schemes_supported", fieldType = "List")

        return WalletMetadata(
            presentationDefinitionURISupported = presentationDefinitionURISupported,
            vpFormatsSupported = vpFormatsSupported,
            clientIdSchemesSupported = clientIdSchemesSupported
        )
    }

    @Generated
    override fun serialize(encoder: Encoder, value: WalletMetadata) {
        val builtInEncoder = encoder.beginStructure(descriptor)

        value.presentationDefinitionURISupported?.let {
            builtInEncoder.encodeBooleanElement(
                descriptor,
                0,
                it
            )
        }
        value.clientIdSchemesSupported?.let {
            builtInEncoder.encodeSerializableElement(
                descriptor,
                2,
                ListSerializer(String.serializer()),
                it
            )
        }
        builtInEncoder.endStructure(descriptor)
    }
}

@Serializable(with = WalletMetadataSerializer::class)
class WalletMetadata(

    @SerialName("presentation_definition_uri_supported")  val presentationDefinitionURISupported: Boolean? = true,
    @SerialName("vp_formats_supported") val vpFormatsSupported: Map<String, VPFormatSupported>,
    @SerialName("client_id_schemes_supported")val clientIdSchemesSupported: List<String>? = listOf(
        ClientIdScheme.PRE_REGISTERED.value),
) : Validatable {
    override fun validate() {
    }
}
@Serializable
data class VPFormatSupported(
    @SerialName("alg_values_supported") val algValuesSupported: List<String>?
)


