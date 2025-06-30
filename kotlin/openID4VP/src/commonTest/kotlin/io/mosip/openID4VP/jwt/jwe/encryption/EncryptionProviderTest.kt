package io.mosip.openID4VP.jwt.jwe.encryption

import com.nimbusds.jose.crypto.X25519Encrypter
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.jwt.exception.JWEException.*
import kotlin.test.*

class EncryptionProviderTest {

    @BeforeTest
    fun setUp() {
        mockkObject(Logger)
        every { Logger.error(any(), any(), any()) } answers { }
    }

    @AfterTest
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

        assertTrue(encrypter is X25519Encrypter)
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

        val exception = assertFailsWith<UnsupportedKeyExchangeAlgorithm> {
            EncryptionProvider.getEncrypter(jwk)
        }

        assertEquals("Required Key exchange algorithm is not supported", exception.message)
    }
}
