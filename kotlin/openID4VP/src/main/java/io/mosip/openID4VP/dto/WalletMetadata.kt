package io.mosip.openID4VP.dto

import io.mosip.openID4VP.authorizationRequest.ClientIdScheme
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
class WalletMetadata(
    @SerialName("presentation_definition_uri_supported")  val presentationDefinitionURISupported: Boolean? = true,
    @SerialName("vp_formats_supported") val vpFormatsSupported: Map<String, VPFormatSupported>,
    @SerialName("client_id_schemes_supported")val clientIdSchemesSupported: List<String>? = listOf(
        ClientIdScheme.PRE_REGISTERED.value),
)

@Serializable
data class VPFormatSupported(
    @SerialName("alg_values_supported") val algValuesSupported: List<String>?
)


