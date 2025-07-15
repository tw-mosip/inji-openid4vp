package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.ClientIdScheme.PRE_REGISTERED
import io.mosip.openID4VP.constants.ContentEncrytionAlgorithm
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.KeyManagementAlgorithm
import io.mosip.openID4VP.constants.RequestSigningAlgorithm
import kotlin.test.*
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

class WalletMetadataTest {


    @Test
    fun `should take default value for presentation_definition_uri_supported if it is null`() {
        val walletMetadata = WalletMetadata(
            presentationDefinitionURISupported = null,
            vpFormatsSupported = mapOf(
                FormatType.LDP_VC to VPFormatSupported(
                    algValuesSupported = listOf("EdDSA")
                )
            ),
            clientIdSchemesSupported = listOf(
                ClientIdScheme.REDIRECT_URI,
                PRE_REGISTERED
            ),
            requestObjectSigningAlgValuesSupported = listOf(RequestSigningAlgorithm.EdDSA),
            authorizationEncryptionAlgValuesSupported = listOf(KeyManagementAlgorithm.ECDH_ES),
            authorizationEncryptionEncValuesSupported = listOf(ContentEncrytionAlgorithm.A256GCM)
        )
        assertEquals(true, walletMetadata.presentationDefinitionURISupported)
    }

    @Test
    fun `should take default value for client_id_schemes_supported if it is null`() {
        val walletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf(
                FormatType.LDP_VC to VPFormatSupported(
                    algValuesSupported = listOf("EdDSA")
                )
            ),
            clientIdSchemesSupported = null,
            requestObjectSigningAlgValuesSupported = listOf(RequestSigningAlgorithm.EdDSA),
            authorizationEncryptionAlgValuesSupported = listOf(KeyManagementAlgorithm.ECDH_ES),
            authorizationEncryptionEncValuesSupported = listOf(ContentEncrytionAlgorithm.A256GCM)
        )
        assertEquals(listOf(PRE_REGISTERED), walletMetadata.clientIdSchemesSupported)
    }

    @Test
    fun `should keep null values for encryption alg and enc if provided`() {
        val walletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf(
                FormatType.LDP_VC to VPFormatSupported(
                    algValuesSupported = listOf("EdDSA")
                )
            ),
            clientIdSchemesSupported = null,
            requestObjectSigningAlgValuesSupported = listOf(RequestSigningAlgorithm.EdDSA),
            authorizationEncryptionAlgValuesSupported = null,
            authorizationEncryptionEncValuesSupported = null
        )
        assertEquals(listOf(PRE_REGISTERED), walletMetadata.clientIdSchemesSupported)
        assertNull(walletMetadata.authorizationEncryptionAlgValuesSupported)
        assertNull(walletMetadata.authorizationEncryptionEncValuesSupported)
    }

    @Test
    fun `should throw error if vp_formats_supported is empty map`() {
        val ex = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            WalletMetadata(
                presentationDefinitionURISupported = true,
                vpFormatsSupported = emptyMap(),
                clientIdSchemesSupported = listOf(
                    ClientIdScheme.REDIRECT_URI,
                    PRE_REGISTERED
                ),
                requestObjectSigningAlgValuesSupported = listOf(RequestSigningAlgorithm.EdDSA),
                authorizationEncryptionAlgValuesSupported = listOf(KeyManagementAlgorithm.ECDH_ES),
                authorizationEncryptionEncValuesSupported = listOf(ContentEncrytionAlgorithm.A256GCM)
            )
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, ex.errorCode)
        assertEquals(
            "vp_formats_supported should at least have one supported vp_format",
            ex.message
        )
    }

}
