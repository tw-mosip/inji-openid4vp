
package io.mosip.openID4VP.authorizationResponse.jwe.keyExchange

import android.util.Log
import com.nimbusds.jose.JWEAlgorithm
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.authorizationResponse.exception.JWEExceptions.UnsupportedKeyExchangeAlgorithm
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows

class KeyExchangeProviderTest {

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
    fun `getAlgorithm returns ECDH-ES for ECDH-ES input`() {
        val algorithm = KeyExchangeProvider.getAlgorithm("ECDH-ES")
        assertEquals(JWEAlgorithm.ECDH_ES, algorithm, "Algorithm should be ECDH-ES")
    }

    @Test
    fun `getAlgorithm throws UnsupportedKeyExchangeAlgorithm for unsupported algorithm`() {
        val unsupportedAlgorithms = listOf(
            "RSA",
            "AES",
            "UNKNOWN",
            ""
        )

        unsupportedAlgorithms.forEach { algorithm ->
            val exception = assertThrows(UnsupportedKeyExchangeAlgorithm::class.java){
                KeyExchangeProvider.getAlgorithm(algorithm)
            }
            assertEquals("Required Key exchange algorithm is not supported", exception.message)
        }
    }
}