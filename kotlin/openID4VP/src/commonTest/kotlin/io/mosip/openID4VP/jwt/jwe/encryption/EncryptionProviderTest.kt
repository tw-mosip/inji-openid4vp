package io.mosip.openID4VP.jwt.jwe.encryption


import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.crypto.X25519Encrypter
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.jwt.exception.JWEException.*
import io.mosip.openID4VP.jwt.jwe.encryption.EncryptionProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

class EncryptionProviderTest {
    @Before
    fun setUp() {
        mockkObject(Logger)
        every { Logger.error(any(), any(), any()) } answers {  }
    }
    @After
    fun tearDown() {
        clearAllMocks()
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

