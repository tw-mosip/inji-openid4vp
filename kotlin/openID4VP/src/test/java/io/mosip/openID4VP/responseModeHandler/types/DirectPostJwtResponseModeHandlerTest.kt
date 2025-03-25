package io.mosip.openID4VP.responseModeHandler.types


import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions.InvalidData
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions.MissingInput
import io.mosip.openID4VP.common.ClientIdScheme
import io.mosip.openID4VP.common.ClientIdScheme.DID
import io.mosip.openID4VP.common.ClientIdScheme.PRE_REGISTERED
import io.mosip.openID4VP.testData.clientMetadataString
import io.mosip.openID4VP.testData.walletMetadata
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows

class DirectPostJwtResponseModeHandlerTest{

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

    @After
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should validate the mandatory fields of clientMetadata` (){
        val clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataSerializer)
        assertDoesNotThrow{
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, false)
        }
    }

    @Test
    fun `should thrown error if jwks field is missing in clientMetadata` (){
        val clientMetadataStr = "{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"vp_formats\":{\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\"]}}}"
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val expectionMessage = "Missing Input: client_metadata->jwks param is required"
        val exception =assertThrows<MissingInput>{
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, false)
        }
        assertEquals(expectionMessage, exception.message)
    }

    @Test
    fun `should thrown error if authorization_encrypted_response_enc field is missing in clientMetadata` (){
        val clientMetadataStr = "{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"vp_formats\":{\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\"]}}}"
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val expectionMessage = "Missing Input: client_metadata->authorization_encrypted_response_enc param is required"
        val exception =assertThrows<MissingInput>{
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, false)
        }
        assertEquals(expectionMessage, exception.message)
    }

    @Test
    fun `should thrown error if authorization_encrypted_response_alg field is missing in clientMetadata` (){
        val clientMetadataStr = "{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"vp_formats\":{\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\"]}}}"
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val expectionMessage = "Missing Input: client_metadata->authorization_encrypted_response_alg param is required"
        val exception =assertThrows<MissingInput>{
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, false)
        }
        assertEquals(expectionMessage, exception.message)
    }

    @Test
    fun `should thrown error if no jwk matching the key encryption algorithm is found` (){
        val clientMetadataStr = "{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"jwks\":{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"X25519\",\"use\":\"enc\",\"x\":\"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4\",\"alg\":\"ECDH\",\"kid\":\"ed-key1\"}]},\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"ES256\"]}}}"
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val expectionMessage = "No jwk matching the specified algorithm found"
        val exception =assertThrows<InvalidData>{
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, false)
        }
        assertEquals(expectionMessage, exception.message)
    }

    @Test
    fun `should validate the fields with walletMetadata` (){
        val clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataSerializer)
        assertDoesNotThrow{
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, true)
        }
    }

    @Test
    fun `should throw error if the key exchange algorithm does not match supported list from the walletMetadata `() {
        val clientMetadataString =
            "{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_alg\":\"ECDH\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"jwks\":{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"X25519\",\"use\":\"enc\",\"x\":\"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4\",\"alg\":\"ECDH\",\"kid\":\"ed-key1\"}]},\"vp_formats\":{\"mso_mdoc\":{},\"ldp_vc\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\"]}}}"

        val clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataSerializer)

        val expectedExceptionMessage =
            "authorization_encrypted_response_alg is not supported"

        val exception = assertThrows<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, true)
        }

        Assertions.assertEquals(expectedExceptionMessage, exception.message)
    }

    @Test
    fun `should throw error if the key exchange algorithm supported list is not provided by wallet and response mode is direct_post_jwt`() {
        val invalidWalletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = emptyMap(),
            clientIdSchemesSupported = listOf(
                ClientIdScheme.REDIRECT_URI.value,
                DID.value,
                PRE_REGISTERED.value
            ),
            requestObjectSigningAlgValuesSupported = listOf("EdDSA"),
            authorizationEncryptionAlgValuesSupported = null,
            authorizationEncryptionEncValuesSupported = listOf("A256GCM")
        )
        val clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataSerializer)
        val expectedExceptionMessage =
            "authorization_encryption_alg_values_supported must be present in wallet_metadata"

        val exception = assertThrows<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, invalidWalletMetadata, true)
        }

        Assertions.assertEquals(expectedExceptionMessage, exception.message)
    }

    @Test
    fun `should throw error if the encryption algorithm does not match supported list from the walletMetadata `() {
        val clientMetadataString =
            "{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256\",\"jwks\":{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"X25519\",\"use\":\"enc\",\"x\":\"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4\",\"alg\":\"ECDH-ES\",\"kid\":\"ed-key1\"}]},\"vp_formats\":{\"mso_mdoc\":{},\"ldp_vc\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\"]}}}"
        val clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataSerializer)


        val expectedExceptionMessage =
            "authorization_encrypted_response_enc is not supported"

        val exception = assertThrows<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, walletMetadata, true)
        }

        Assertions.assertEquals(expectedExceptionMessage, exception.message)
    }

    @Test
    fun `should throw error if the encryption algorithm supported list is not provided by wallet and response mode is direct_post_jwt`() {
        val clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataSerializer)
        val invalidWalletMetadata = WalletMetadata(
            presentationDefinitionURISupported = true,
            vpFormatsSupported = emptyMap(),
            clientIdSchemesSupported = listOf(
                ClientIdScheme.REDIRECT_URI.value,
                DID.value,
                PRE_REGISTERED.value
            ),
            requestObjectSigningAlgValuesSupported = listOf("EdDSA"),
            authorizationEncryptionAlgValuesSupported = listOf("ECDH-ES"),
            authorizationEncryptionEncValuesSupported = null
        )
        val expectedExceptionMessage =
            "authorization_encryption_enc_values_supported must be present in wallet_metadata"

        val exception = assertThrows<InvalidData> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata, invalidWalletMetadata, true)
        }

        Assertions.assertEquals(expectedExceptionMessage, exception.message)
    }


}