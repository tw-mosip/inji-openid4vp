package io.mosip.openID4VP.authorizationRequest

import com.fasterxml.jackson.annotation.JsonProperty
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.ContentEncrytionAlgorithm
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.KeyManagementAlgorithm
import io.mosip.openID4VP.constants.RequestSigningAlgorithm
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private val className = WalletMetadata::class.simpleName!!

data class WalletMetadata(
    @JsonProperty("presentation_definition_uri_supported") val presentationDefinitionURISupported: Boolean = true,
    @JsonProperty("vp_formats_supported") val vpFormatsSupported: Map<FormatType, VPFormatSupported>,
    @JsonProperty("client_id_schemes_supported") val clientIdSchemesSupported: List<ClientIdScheme> = listOf(
        ClientIdScheme.PRE_REGISTERED
    ),
    @JsonProperty("request_object_signing_alg_values_supported") var requestObjectSigningAlgValuesSupported: List<RequestSigningAlgorithm>? = null,
    @JsonProperty("authorization_encryption_alg_values_supported") val authorizationEncryptionAlgValuesSupported: List<KeyManagementAlgorithm>? = null,
    @JsonProperty("authorization_encryption_enc_values_supported") val authorizationEncryptionEncValuesSupported: List<ContentEncrytionAlgorithm>? = null
) {
    init {
        require(vpFormatsSupported.isNotEmpty()) {
            throw OpenID4VPExceptions.InvalidData(
                "vp_formats_supported should at least have one supported vp_format",
                className
            )
        }
    }

    constructor(
        presentationDefinitionURISupported: Boolean?,
        vpFormatsSupported: Map<FormatType, VPFormatSupported>,
        clientIdSchemesSupported: List<ClientIdScheme>?,
        requestObjectSigningAlgValuesSupported: List<RequestSigningAlgorithm>?,
        authorizationEncryptionAlgValuesSupported: List<KeyManagementAlgorithm>?,
        authorizationEncryptionEncValuesSupported: List<ContentEncrytionAlgorithm>?
    ) : this(
        presentationDefinitionURISupported = presentationDefinitionURISupported ?: true,
        vpFormatsSupported = vpFormatsSupported,
        clientIdSchemesSupported = clientIdSchemesSupported
            ?: listOf(ClientIdScheme.PRE_REGISTERED),
        requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported,
        authorizationEncryptionAlgValuesSupported = authorizationEncryptionAlgValuesSupported,
        authorizationEncryptionEncValuesSupported = authorizationEncryptionEncValuesSupported
    )
}

data class VPFormatSupported(
    @JsonProperty("alg_values_supported") val algValuesSupported: List<String>? = null
)
