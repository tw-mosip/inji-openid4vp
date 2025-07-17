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
    @JsonProperty("client_id_schemes_supported") var clientIdSchemesSupported: List<ClientIdScheme> ? = null,
    @JsonProperty("request_object_signing_alg_values_supported") var requestObjectSigningAlgValuesSupported: List<RequestSigningAlgorithm>? = null,
    @JsonProperty("authorization_encryption_alg_values_supported") var authorizationEncryptionAlgValuesSupported: List<KeyManagementAlgorithm>? = null,
    @JsonProperty("authorization_encryption_enc_values_supported") var authorizationEncryptionEncValuesSupported: List<ContentEncrytionAlgorithm>? = null
) {
    init {
        require(vpFormatsSupported.isNotEmpty()) {
            throw OpenID4VPExceptions.InvalidData(
                "vp_formats_supported should at least have one supported vp_format", className
            )
        }
        clientIdSchemesSupported = clientIdSchemesSupported
            ?: getClientIdSchemesSupported()
        requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported
            ?: getRequestObjectSigningAlgValuesSupported()
        authorizationEncryptionEncValuesSupported = authorizationEncryptionEncValuesSupported
            ?: getAuthorizationEncryptionEncValuesSupported()
        authorizationEncryptionAlgValuesSupported = authorizationEncryptionAlgValuesSupported
            ?: getAuthorizationEncryptionAlgValuesSupported()
    }


    companion object {
        fun construct(vpSigningAlgorithmSupported: Map<FormatType, List<String>>?): WalletMetadata {
            val vpFormatsSupported = mutableMapOf<FormatType, VPFormatSupported>()
            if (vpSigningAlgorithmSupported.isNullOrEmpty()) {
                throw OpenID4VPExceptions.InvalidData(
                    "vpSigningAlgorithmSupported should at least have one supported format type",
                    className
                )
            }
            vpSigningAlgorithmSupported.forEach { (formatType, signingAlgorithms) ->
                if (signingAlgorithms.isEmpty()) {
                    throw OpenID4VPExceptions.InvalidData(
                        "Signing Algorithm supported for $formatType should not be empty",
                        className
                    )
                }
                vpFormatsSupported[formatType] = VPFormatSupported(
                    algValuesSupported = signingAlgorithms
                )
            }
            return WalletMetadata(
                vpFormatsSupported = vpFormatsSupported
            )
        }
    }
}

data class VPFormatSupported(
    @JsonProperty("alg_values_supported") val algValuesSupported: List<String>? = null
)

private fun getRequestObjectSigningAlgValuesSupported() =
    listOf(RequestSigningAlgorithm.EdDSA)

private fun getAuthorizationEncryptionAlgValuesSupported() =
    listOf(KeyManagementAlgorithm.ECDH_ES)

private fun getAuthorizationEncryptionEncValuesSupported() =
    listOf(ContentEncrytionAlgorithm.A256GCM)

private fun getClientIdSchemesSupported() =
    listOf(ClientIdScheme.PRE_REGISTERED, ClientIdScheme.DID, ClientIdScheme.REDIRECT_URI)


