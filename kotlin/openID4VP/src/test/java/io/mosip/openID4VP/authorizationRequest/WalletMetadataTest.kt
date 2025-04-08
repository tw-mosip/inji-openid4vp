package io.mosip.openID4VP.authorizationRequest

import android.util.Log
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.ClientIdScheme.PRE_REGISTERED
import io.mosip.openID4VP.exceptions.Exceptions.InvalidData
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.assertThrows

class WalletMetadataTest {
    @Before
    fun setUp() {
        mockkStatic(android.util.Log::class)
        every { Log.e(any(), any()) } answers {
            val tag = arg<String>(0)
            val msg = arg<String>(1)
            println("Error: logTag: $tag | Message: $msg")
            0
        }
        every { Log.d(any(), any()) } answers {
            val tag = arg<String>(0)
            val msg = arg<String>(1)
            println("Error: logTag: $tag | Message: $msg")
            0
        }
    }

    @Test
    fun `should take default value for presentation_definition_uri_supported if it is null`() {
        val walletMetadata = WalletMetadata(
            presentationDefinitionURISupported = null,
            vpFormatsSupported = mapOf(
                "ldp_vc" to VPFormatSupported(
                    algValuesSupported = listOf("EdDSA")
                )
            ),
            clientIdSchemesSupported = listOf(
                ClientIdScheme.REDIRECT_URI.value,
                PRE_REGISTERED.value
            ),
            requestObjectSigningAlgValuesSupported = listOf("EdDSA"),
            authorizationEncryptionAlgValuesSupported = listOf("ECDH-ES"),
            authorizationEncryptionEncValuesSupported = listOf("A256GCM")
        )
        assertEquals(walletMetadata.presentationDefinitionURISupported, true)
    }

    @Test
    fun `should take default value for client_id_schemes_supported if it is null`() {
        val walletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf(
                "ldp_vc" to VPFormatSupported(
                    algValuesSupported = listOf("EdDSA")
                )
            ),
            clientIdSchemesSupported = null,
            requestObjectSigningAlgValuesSupported = listOf("EdDSA"),
            authorizationEncryptionAlgValuesSupported = listOf("ECDH-ES"),
            authorizationEncryptionEncValuesSupported = listOf("A256GCM")
        )
        assertEquals(walletMetadata.clientIdSchemesSupported, listOf(PRE_REGISTERED.value))
    }

    @Test
    fun `should keep null value for authorization_encryption_enc_values_supported and authorization_encryption_alg_values_supported if provided` () {
        val walletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = mapOf(
                "ldp_vc" to VPFormatSupported(
                    algValuesSupported = listOf("EdDSA")
                )
            ),
            clientIdSchemesSupported = null,
            requestObjectSigningAlgValuesSupported = listOf("EdDSA"),
            authorizationEncryptionAlgValuesSupported = null,
            authorizationEncryptionEncValuesSupported = null
        )
        assertEquals(walletMetadata.clientIdSchemesSupported, listOf(PRE_REGISTERED.value))
    }

    @Test
    fun `should throw error if vp_formats_supported is empty map`(): Unit {
        val exception = assertThrows<InvalidData> {
            WalletMetadata(
                presentationDefinitionURISupported = true,
                vpFormatsSupported = emptyMap(),
                clientIdSchemesSupported = listOf(
                    ClientIdScheme.REDIRECT_URI.value,
                    PRE_REGISTERED.value
                ),
                requestObjectSigningAlgValuesSupported = listOf("EdDSA"),
                authorizationEncryptionAlgValuesSupported = listOf("ECDH-ES"),
                authorizationEncryptionEncValuesSupported = listOf("A256GCM")
            )
        }
        assertEquals(
            "vp_formats_supported should at least have one supported vp_format",
            exception.message
        )
    }
}