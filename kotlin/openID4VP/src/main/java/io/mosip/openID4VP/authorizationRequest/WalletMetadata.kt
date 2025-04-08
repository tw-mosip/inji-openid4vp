package io.mosip.openID4VP.authorizationRequest

import com.fasterxml.jackson.annotation.JsonProperty
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.constants.ClientIdScheme

private val className = WalletMetadata::class.simpleName!!

data class WalletMetadata(
    @JsonProperty("presentation_definition_uri_supported") val presentationDefinitionURISupported: Boolean = true,
    @JsonProperty("vp_formats_supported") val vpFormatsSupported: Map<String, VPFormatSupported>,
    @JsonProperty("client_id_schemes_supported") val clientIdSchemesSupported: List<String> = listOf(
        ClientIdScheme.PRE_REGISTERED.value
    ),
    @JsonProperty("request_object_signing_alg_values_supported") var requestObjectSigningAlgValuesSupported: List<String>? = null,
    @JsonProperty("authorization_encryption_alg_values_supported") val authorizationEncryptionAlgValuesSupported: List<String>? = null,
    @JsonProperty("authorization_encryption_enc_values_supported") val authorizationEncryptionEncValuesSupported: List<String>? = null
){
    init {
        require(vpFormatsSupported.isNotEmpty()) {
            throw Logger.handleException(
                exceptionType = "InvalidData",
                className = className,
                message = "vp_formats_supported should at least have one supported vp_format"
            )
        }
    }
    constructor(
        presentationDefinitionURISupported: Boolean?,
        vpFormatsSupported: Map<String, VPFormatSupported>,
        clientIdSchemesSupported: List<String>?,
        requestObjectSigningAlgValuesSupported: List<String>?,
        authorizationEncryptionAlgValuesSupported: List<String>?,
        authorizationEncryptionEncValuesSupported: List<String>?
    ) : this(
        presentationDefinitionURISupported=presentationDefinitionURISupported ?: true,
        vpFormatsSupported = vpFormatsSupported,
        clientIdSchemesSupported = clientIdSchemesSupported ?: listOf(ClientIdScheme.PRE_REGISTERED.value),
        requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported,
        authorizationEncryptionAlgValuesSupported = authorizationEncryptionAlgValuesSupported,
        authorizationEncryptionEncValuesSupported = authorizationEncryptionEncValuesSupported
    )
}
data class VPFormatSupported(
    @JsonProperty("alg_values_supported") val algValuesSupported: List<String>? = null
)
