package io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.mockkObject
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.validateField
import io.mosip.openID4VP.exceptions.Exceptions.InvalidInput
import org.junit.After
import org.junit.Before
import org.junit.Test

class VPResponseMetadataTest {

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        mockkStatic(::validateField)
        mockkObject(Logger)

        every { Log.e(any(), any()) } returns 0
        every { Log.d(any(), any()) } returns 0

        every { validateField(any(), "String") } answers {
            val value = arg<String?>(0)
            value != null && value.isNotEmpty()
        }

        every {
            Logger.handleException(any(), any(), any(), any())
        } returns InvalidInput("", "Validation failed")
    }

    @After
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should create valid instance with all valid fields`() {
        val metadata = VPResponseMetadata(
            jws = "valid-jws-value",
            signatureAlgorithm = "ES256",
            publicKey = "valid-public-key",
            domain = "example.com"
        )

        // Should not throw exception
        metadata.validate()
    }

    @Test(expected = InvalidInput::class)
    fun `should throw exception when jws is empty`() {
        val metadata = VPResponseMetadata(
            jws = "",
            signatureAlgorithm = "ES256",
            publicKey = "valid-public-key",
            domain = "example.com"
        )

        metadata.validate()
    }

    @Test(expected = InvalidInput::class)
    fun `should throw exception when jws is null string`() {
        val metadata = VPResponseMetadata(
            jws = "null",
            signatureAlgorithm = "ES256",
            publicKey = "valid-public-key",
            domain = "example.com"
        )

        metadata.validate()
    }

    @Test(expected = InvalidInput::class)
    fun `should throw exception when signatureAlgorithm is empty`() {
        val metadata = VPResponseMetadata(
            jws = "valid-jws-value",
            signatureAlgorithm = "",
            publicKey = "valid-public-key",
            domain = "example.com"
        )

        metadata.validate()
    }

    @Test(expected = InvalidInput::class)
    fun `should throw exception when signatureAlgorithm is null string`() {
        val metadata = VPResponseMetadata(
            jws = "valid-jws-value",
            signatureAlgorithm = "null",
            publicKey = "valid-public-key",
            domain = "example.com"
        )

        metadata.validate()
    }

    @Test(expected = InvalidInput::class)
    fun `should throw exception when publicKey is empty`() {
        val metadata = VPResponseMetadata(
            jws = "valid-jws-value",
            signatureAlgorithm = "ES256",
            publicKey = "",
            domain = "example.com"
        )

        metadata.validate()
    }

    @Test(expected = InvalidInput::class)
    fun `should throw exception when publicKey is null string`() {
        val metadata = VPResponseMetadata(
            jws = "valid-jws-value",
            signatureAlgorithm = "ES256",
            publicKey = "null",
            domain = "example.com"
        )

        metadata.validate()
    }

    @Test(expected = InvalidInput::class)
    fun `should throw exception when domain is empty`() {
        val metadata = VPResponseMetadata(
            jws = "valid-jws-value",
            signatureAlgorithm = "ES256",
            publicKey = "valid-public-key",
            domain = ""
        )

        metadata.validate()
    }

    @Test(expected = InvalidInput::class)
    fun `should throw exception when domain is null string`() {
        val metadata = VPResponseMetadata(
            jws = "valid-jws-value",
            signatureAlgorithm = "ES256",
            publicKey = "valid-public-key",
            domain = "null"
        )

        metadata.validate()
    }
}