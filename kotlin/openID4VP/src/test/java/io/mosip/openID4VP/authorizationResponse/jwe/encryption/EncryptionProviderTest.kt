package io.mosip.openID4VP.authorizationResponse.jwe.encryption

import android.util.Log
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.crypto.X25519Encrypter
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.jwe.exception.JWEExceptions.UnsupportedEncryptionAlgorithm
import io.mosip.openID4VP.jwe.exception.JWEExceptions.UnsupportedKeyExchangeAlgorithm
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

class EncryptionProviderTest {
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
    fun `getMethod should return A256GCM for A256GCM input`() {
        assertEquals(EncryptionMethod.A256GCM, EncryptionProvider.getMethod("A256GCM"))
    }

    @Test
    fun `getMethod should throw UnsupportedEncryptionAlgorithm for unsupported method`() {
        assertThrows(UnsupportedEncryptionAlgorithm::class.java)  {
            EncryptionProvider.getMethod("UNSUPPORTED")
        }
    }

    @Test
    fun `getEncrypter should create X25519Encrypter for OKP key type`() {
        val jwk = Jwk(
            alg = "ECDH-ES",
            kty = "OKP",
            use = "enc",
            crv = "X25519",
            x = "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
            kid = "ed-key1"
        )
        val encrypter = EncryptionProvider.getEncrypter(jwk)

        assert(encrypter is X25519Encrypter)
    }

    @Test
    fun `getEncrypter should throw UnsupportedKeyExchangeAlgorithm for non-OKP key type`() {
        val jwk = Jwk(
            alg = "ECDH-ES",
            kty = "UNSUPPORTED",
            use = "enc",
            crv = "X25519",
            x = "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
            kid = "ed-key1"
        )

        val exception = assertThrows(UnsupportedKeyExchangeAlgorithm::class.java) {
            EncryptionProvider.getEncrypter(jwk)
        }

        assertEquals("Required Key exchange algorithm is not supported", exception.message)
    }

}

