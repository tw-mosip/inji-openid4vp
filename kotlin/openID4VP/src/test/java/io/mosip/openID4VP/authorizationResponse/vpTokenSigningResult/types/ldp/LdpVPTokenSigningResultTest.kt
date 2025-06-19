package io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.mockkObject
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.validateField
import io.mosip.openID4VP.constants.SignatureAlgorithm
import io.mosip.openID4VP.exceptions.Exceptions.InvalidInput
import org.junit.After
import org.junit.Before
import org.junit.Test

class LdpVPTokenSigningResultTest {

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
        } returns InvalidInput("","Validation failed")
    }

    @After
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should create valid instance with Ed25519Signature2020 and proofValue`() {
        val result = LdpVPTokenSigningResult(
            proofValue = "valid-proof-value",
            signatureAlgorithm = SignatureAlgorithm.Ed25519Signature2020.value
        )

        // Should not throw exception
        result.validate()
    }

    @Test
    fun `should create valid instance with JsonWebSignature2020 and jws`() {
        val result = LdpVPTokenSigningResult(
            jws = "valid-jws",
            signatureAlgorithm = SignatureAlgorithm.JsonWebSignature2020.value
        )

        // Should not throw exception
        result.validate()
    }

    @Test(expected = InvalidInput::class)
    fun `should throw exception when proofValue is null string for Ed25519Signature2020`() {
        val result = LdpVPTokenSigningResult(
            proofValue = "null",
            signatureAlgorithm = SignatureAlgorithm.Ed25519Signature2020.value
        )

        result.validate()
    }

    @Test(expected = InvalidInput::class)
    fun `should throw exception when proofValue is null for Ed25519Signature2020`() {
        val result = LdpVPTokenSigningResult(
            proofValue = null,
            signatureAlgorithm = SignatureAlgorithm.Ed25519Signature2020.value
        )

        result.validate()
    }

    @Test(expected = InvalidInput::class)
    fun `should throw exception when proofValue is empty for Ed25519Signature2020`() {
        val result = LdpVPTokenSigningResult(
            proofValue = "",
            signatureAlgorithm = SignatureAlgorithm.Ed25519Signature2020.value
        )

        result.validate()
    }

    @Test(expected = InvalidInput::class)
    fun `should throw exception when jws is null string for JsonWebSignature2020`() {
        val result = LdpVPTokenSigningResult(
            jws = "null",
            signatureAlgorithm = SignatureAlgorithm.JsonWebSignature2020.value
        )

        result.validate()
    }

    @Test(expected = InvalidInput::class)
    fun `should throw exception when jws is null for JsonWebSignature2020`() {
        val result = LdpVPTokenSigningResult(
            jws = null,
            signatureAlgorithm = SignatureAlgorithm.JsonWebSignature2020.value
        )

        result.validate()
    }

    @Test(expected = InvalidInput::class)
    fun `should throw exception when jws is empty for JsonWebSignature2020`() {
        val result = LdpVPTokenSigningResult(
            jws = "",
            signatureAlgorithm = SignatureAlgorithm.JsonWebSignature2020.value
        )

        result.validate()
    }

    @Test
    fun `should handle both jws and proofValue present`() {
        val result = LdpVPTokenSigningResult(
            jws = "valid-jws",
            proofValue = "valid-proof-value",
            signatureAlgorithm = SignatureAlgorithm.Ed25519Signature2020.value
        )

        // Should validate proofValue and ignore jws for Ed25519Signature2020
        result.validate()
    }
}