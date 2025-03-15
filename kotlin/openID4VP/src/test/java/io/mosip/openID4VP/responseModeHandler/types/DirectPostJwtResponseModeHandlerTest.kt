package io.mosip.openID4VP.responseModeHandler.types


import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.exceptions.Exceptions.InvalidData
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions.MissingInput
import io.mosip.openID4VP.testData.clientMetadataString
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.assertThrows

class DirectPostJwtResponseModeHandlerTest {

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

    /** validation of client metadata **/

    @Test
    fun `should validate the mandatory fields of clientMetadata`() {
        val clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataSerializer)
        assertDoesNotThrow{
            DirectPostJwtResponseModeHandler().validate(clientMetadata)
        }
    }

    @Test
    fun `should thrown error if jwks field is missing in clientMetadata` (){
        val clientMetadataStr = "{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"vp_formats\":{\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\"]}}}"
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exceptionMessage = "Missing Input: client_metadata->jwks param is required"
        val exception =assertThrows<MissingInput>{
            DirectPostJwtResponseModeHandler().validate(clientMetadata)
        }
        assertEquals(exceptionMessage, exception.message)
    }

    @Test
    fun `should thrown error if authorization_encrypted_response_enc field is missing in clientMetadata` (){
        val clientMetadataStr = "{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"vp_formats\":{\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\"]}}}"
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exceptionMessage = "Missing Input: client_metadata->authorization_encrypted_response_enc param is required"
        val exception =assertThrows<MissingInput>{
            DirectPostJwtResponseModeHandler().validate(clientMetadata)
        }
        assertEquals(exceptionMessage, exception.message)
    }

    @Test
    fun `should thrown error if authorization_encrypted_response_alg field is missing in clientMetadata` (){
        val clientMetadataStr = "{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"vp_formats\":{\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\"]}}}"
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val exceptionMessage =
            "Missing Input: client_metadata->authorization_encrypted_response_alg param is required"
        val exception = assertThrows<MissingInput> {
            DirectPostJwtResponseModeHandler().validate(clientMetadata)
        }
        assertEquals(exceptionMessage, exception.message)
    }

    @Test
    fun `should thrown error if no jwk matching the key encryption algorithm is found` (){
        val clientMetadataStr = "{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"jwks\":{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"X25519\",\"use\":\"enc\",\"x\":\"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4\",\"alg\":\"ECDH\",\"kid\":\"ed-key1\"}]},\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"ES256\"]}}}"
        val clientMetadata = deserializeAndValidate(clientMetadataStr, ClientMetadataSerializer)

        val expectionMessage = "No jwk matching the specified algorithm found"
        val exception =assertThrows<InvalidData>{
            DirectPostJwtResponseModeHandler().validate(clientMetadata)
        }
        assertEquals(expectionMessage, exception.message)
    }
}