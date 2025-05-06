package io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.exceptions.Exceptions.InvalidInput
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.assertThrows

class LdpVpTokenSigningResultTest {

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
    fun `should create LdpVpTokenSigningResult with valid parameters`() {
        val ldpVpTokenSigningResult = LdpVpTokenSigningResult(
            jws = "eyJhbGciOiJ..MDIyfQ",
            signatureAlgorithm = "ES256",
            publicKey = "-----BEGIN PUBLIC KEY-----\nMFk...dT9POxg==\n-----END PUBLIC KEY-----",
            domain = "example.com"
        )

        assertEquals("eyJhbGciOiJ..MDIyfQ", ldpVpTokenSigningResult.jws)
        assertEquals("ES256", ldpVpTokenSigningResult.signatureAlgorithm)
        assertTrue(ldpVpTokenSigningResult.publicKey.startsWith("-----BEGIN PUBLIC KEY-----"))
        assertEquals("example.com", ldpVpTokenSigningResult.domain)

        assertDoesNotThrow { ldpVpTokenSigningResult.validate() }
    }

    @Test
    fun `should throw exception when jws is invalid`() {
        val ldpVpTokenSigningResult = LdpVpTokenSigningResult(
            jws = "null",
            signatureAlgorithm = "ES256",
            publicKey = "valid-key",
            domain = "example.com"
        )

        val exception = assertThrows<InvalidInput> {
            ldpVpTokenSigningResult.validate()
        }

        assertEquals("Invalid Input: ldp_vp_token_signing_result->jws value cannot be an empty string, null, or an integer", exception.message)
    }

    @Test
    fun `should throw exception when signatureAlgorithm is invalid`() {
        val ldpVpTokenSigningResult = LdpVpTokenSigningResult(
            jws = "valid-jws",
            signatureAlgorithm = "null",
            publicKey = "valid-key",
            domain = "example.com"
        )

        val exception = assertThrows<InvalidInput> {
            ldpVpTokenSigningResult.validate()
        }

        assertEquals("Invalid Input: ldp_vp_token_signing_result->signatureAlgorithm value cannot be an empty string, null, or an integer", exception.message)

    }

    @Test
    fun `should throw exception when publicKey is invalid`() {
        val ldpVpTokenSigningResult = LdpVpTokenSigningResult(
            jws = "valid-jws",
            signatureAlgorithm = "ES256",
            publicKey = "null",
            domain = "example.com"
        )

        val exception = assertThrows<InvalidInput> {
            ldpVpTokenSigningResult.validate()
        }

        assertEquals("Invalid Input: ldp_vp_token_signing_result->publicKey value cannot be an empty string, null, or an integer", exception.message)
    }

    @Test
    fun `should throw exception when domain is invalid`() {
        val ldpVpTokenSigningResult = LdpVpTokenSigningResult(
            jws = "valid-jws",
            signatureAlgorithm = "ES256",
            publicKey = "valid-key",
            domain = "null"
        )

        val exception = assertThrows<InvalidInput> {
            ldpVpTokenSigningResult.validate()
        }

        assertEquals("Invalid Input: ldp_vp_token_signing_result->domain value cannot be an empty string, null, or an integer", exception.message)
    }
}