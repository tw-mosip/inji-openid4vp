package io.mosip.openID4VP.authorizationResponse.authenticationContainer.types.ldp

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.exceptions.Exceptions
import io.mosip.openID4VP.exceptions.Exceptions.InvalidInput
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.assertThrows

class LdpAuthenticationContainerTest {

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
    fun `should create container with valid parameters`() {
        val container = LdpAuthenticationContainer(
            jws = "eyJhbGciOiJ..MDIyfQ",
            signatureAlgorithm = "ES256",
            publicKey = "-----BEGIN PUBLIC KEY-----\nMFk...dT9POxg==\n-----END PUBLIC KEY-----",
            domain = "example.com"
        )

        assertEquals("eyJhbGciOiJ..MDIyfQ", container.jws)
        assertEquals("ES256", container.signatureAlgorithm)
        assertTrue(container.publicKey.startsWith("-----BEGIN PUBLIC KEY-----"))
        assertEquals("example.com", container.domain)

        assertDoesNotThrow { container.validate() }
    }

    @Test
    fun `should throw exception when jws is invalid`() {
        val container = LdpAuthenticationContainer(
            jws = "null",
            signatureAlgorithm = "ES256",
            publicKey = "valid-key",
            domain = "example.com"
        )

        val exception = assertThrows<InvalidInput> {
            container.validate()
        }

        assertEquals("Invalid Input: ldp_authentication_container->jws value cannot be an empty string, null, or an integer", exception.message)
    }

    @Test
    fun `should throw exception when signatureAlgorithm is invalid`() {
        val container = LdpAuthenticationContainer(
            jws = "valid-jws",
            signatureAlgorithm = "null",
            publicKey = "valid-key",
            domain = "example.com"
        )

        val exception = assertThrows<InvalidInput> {
            container.validate()
        }

        assertEquals("Invalid Input: ldp_authentication_container->signatureAlgorithm value cannot be an empty string, null, or an integer", exception.message)

    }

    @Test
    fun `should throw exception when publicKey is invalid`() {
        val container = LdpAuthenticationContainer(
            jws = "valid-jws",
            signatureAlgorithm = "ES256",
            publicKey = "null",
            domain = "example.com"
        )

        val exception = assertThrows<InvalidInput> {
            container.validate()
        }

        assertEquals("Invalid Input: ldp_authentication_container->publicKey value cannot be an empty string, null, or an integer", exception.message)
    }

    @Test
    fun `should throw exception when domain is invalid`() {
        val container = LdpAuthenticationContainer(
            jws = "valid-jws",
            signatureAlgorithm = "ES256",
            publicKey = "valid-key",
            domain = "null"
        )

        val exception = assertThrows<InvalidInput> {
            container.validate()
        }

        assertEquals("Invalid Input: ldp_authentication_container->domain value cannot be an empty string, null, or an integer", exception.message)
    }
}