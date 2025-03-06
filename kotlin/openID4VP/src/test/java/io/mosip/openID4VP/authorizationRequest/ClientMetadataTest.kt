package io.mosip.openID4VP.authorizationRequest

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.clientMetadata.parseAndValidateClientMetadata
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions.*
import io.mosip.openID4VP.common.ResponseMode.DIRECT_POST_JWT
import io.mosip.openID4VP.testData.clientMetadataString
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.assertDoesNotThrow

class ClientMetadataTest {
	private lateinit var actualException: Exception

	@Before
	fun setUp() {
		mockkStatic(Log::class)
		every { Log.e(any(), any()) } answers {
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
	fun `should parse client metadata successfully`() {
		assertDoesNotThrow {
			 deserializeAndValidate(clientMetadataString,ClientMetadataSerializer)
		}
	}

	@Test
	fun `should throw invalid input exception if vp_formats field is not available`() {
		val invalidClientMetadata = "{\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\"}"

		val expectedExceptionMessage =
			"Invalid Input: client_metadata->vp_formats value cannot be empty or null"

		actualException =
			Assert.assertThrows(InvalidInput::class.java) {
				deserializeAndValidate(invalidClientMetadata, ClientMetadataSerializer)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw invalid input exception if name field is available in client_metadata but the value is empty`() {
		val invalidClientMetadata =  "{\"client_name\":\"\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"ES256\",\"EdDSA\"]},\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\",\"RsaSignature2018\"]}}}"

		val expectedExceptionMessage =
			"Invalid Input: client_metadata->client_name value cannot be an empty string, null, or an integer"

		actualException =
			Assert.assertThrows(InvalidInput::class.java) {
				deserializeAndValidate(invalidClientMetadata, ClientMetadataSerializer)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw invalid input exception if name field is available in client_metadata but the value is null`() {

		val invalidClientMetadata = "{\"client_name\":null,\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"ES256\",\"EdDSA\"]},\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\",\"RsaSignature2018\"]}}}"

		val expectedExceptionMessage =
			"Invalid Input: client_metadata->client_name value cannot be an empty string, null, or an integer"

		actualException =
			Assert.assertThrows(InvalidInput::class.java) {
				deserializeAndValidate(invalidClientMetadata, ClientMetadataSerializer)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw invalid input exception if log_url field is available in client_metadata but the value is empty`() {
		val invalidClientMetadata = "{\"client_name\":\"\",\"client_name\":\"verifier\",\"logo_uri\":\"\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"ES256\",\"EdDSA\"]},\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\",\"RsaSignature2018\"]}}}"

		val expectedExceptionMessage =
			"Invalid Input: client_metadata->logo_uri value cannot be an empty string, null, or an integer"

		actualException =
			Assert.assertThrows(InvalidInput::class.java) {
				deserializeAndValidate(invalidClientMetadata, ClientMetadataSerializer)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw missing input exception if encryption algorithm is missing for response mode is direct_post jwt`() {
		val invalidClientMetadata  =
			"{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"jwks\":{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"X25519\",\"use\":\"enc\",\"x\":\"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4\",\"alg\":\"ECDH-ES\",\"kid\":\"ed-key1\"}]},\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"EdDSA\"]}}}"
		val authorizationRequestParam : MutableMap<String, Any> = mutableMapOf(
			CLIENT_METADATA.value to invalidClientMetadata,
			RESPONSE_MODE.value to DIRECT_POST_JWT.value
		)
		val expectedExceptionMessage =
			"Missing Input: client_metadata->authorization_encrypted_response_alg param is required"

		actualException =
			Assert.assertThrows(MissingInput::class.java) {
				parseAndValidateClientMetadata(authorizationRequestParam)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw missing input exception if encryption encoding value is missing for response mode is direct_post jwt`() {
		val invalidClientMetadata  =
			"{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"jwks\":{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"X25519\",\"use\":\"enc\",\"x\":\"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4\",\"alg\":\"ECDH-ES\",\"kid\":\"ed-key1\"}]},\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"EdDSA\"]}}}"
		val authorizationRequestParam : MutableMap<String, Any> = mutableMapOf(
			CLIENT_METADATA.value to invalidClientMetadata,
			RESPONSE_MODE.value to DIRECT_POST_JWT.value
		)
		val expectedExceptionMessage =
			"Missing Input: client_metadata->authorization_encrypted_response_enc param is required"

		actualException =
			Assert.assertThrows(MissingInput::class.java) {
				parseAndValidateClientMetadata(authorizationRequestParam)
			}
		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw missing input exception if jwks field is missing for response mode is direct_post jwt`() {
		val invalidClientMetadata  =
			"{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"AES256GCM\",\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"EdDSA\"]}}}"
		val authorizationRequestParam : MutableMap<String, Any> = mutableMapOf(
			CLIENT_METADATA.value to invalidClientMetadata,
			RESPONSE_MODE.value to DIRECT_POST_JWT.value
		)
		val expectedExceptionMessage =
			"Missing Input: client_metadata->jwks param is required"

		actualException =
			Assert.assertThrows(MissingInput::class.java) {
				parseAndValidateClientMetadata(authorizationRequestParam)
			}
		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw missing input exception if jwk matching the algorithm field is missing in jwks for response mode is direct_post jwt`() {
		val invalidClientMetadata  =
			"{\"client_name\":\"Requestername\",\"logo_uri\":\"<logo_uri>\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"authorization_encrypted_response_alg\":\"ECDH\",\"jwks\":{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"X25519\",\"use\":\"enc\",\"x\":\"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4\",\"alg\":\"ECDH-ES\",\"kid\":\"ed-key1\"}]},\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"EdDSA\"]}}}"
		val authorizationRequestParam : MutableMap<String, Any> = mutableMapOf(
			CLIENT_METADATA.value to invalidClientMetadata,
			RESPONSE_MODE.value to DIRECT_POST_JWT.value
		)
		val expectedExceptionMessage =
			"No jwk matching the specified algorithm found"

		actualException =
			Assert.assertThrows(InvalidData::class.java) {
				parseAndValidateClientMetadata(authorizationRequestParam)
			}
		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw InvalidData exception if client metadata is not of string or map type`() {
		val invalidClientMetadata  = true
		val authorizationRequestParam : MutableMap<String, Any> = mutableMapOf(
			CLIENT_METADATA.value to invalidClientMetadata,
			RESPONSE_MODE.value to DIRECT_POST_JWT.value
		)
		val expectedExceptionMessage =
			"client_metadata must be of type String or Map"

		actualException =
			Assert.assertThrows(InvalidData::class.java) {
				parseAndValidateClientMetadata(authorizationRequestParam)
			}
		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw InvalidData exception if client metadata is not present for response mode direct_post jwt`() {
		val authorizationRequestParam : MutableMap<String, Any> = mutableMapOf(
			RESPONSE_MODE.value to DIRECT_POST_JWT.value
		)
		val expectedExceptionMessage =
			"client_metadata must be present for given response mode"

		actualException =
			Assert.assertThrows(InvalidData::class.java) {
				parseAndValidateClientMetadata(authorizationRequestParam)
			}
		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}


}