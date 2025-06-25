package io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc


import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.exceptions.Exceptions.InvalidInput
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.assertThrows


class DeviceAuthenticationTest {

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
    fun `validate succeeds with valid inputs`() {
        val deviceAuth = DeviceAuthentication("testSignature", "SHA256withRSA")
        assertDoesNotThrow { deviceAuth.validate() }
    }

    @Test
    fun `validate throws exception with null signature string`() {
        val deviceAuth = DeviceAuthentication("null", "SHA256withRSA")

        val exception = assertThrows<InvalidInput> {
            deviceAuth.validate()
        }
        assertEquals("Invalid Input: mdoc_vp_token_signing_result->device_authentication->signature value cannot be empty or null", exception.message)
    }

    @Test
    fun `validate throws exception with null algorithm string`() {
        val deviceAuth = DeviceAuthentication("testSignature", "null")

        val exception = assertThrows<InvalidInput> {
            deviceAuth.validate()
        }
        assertEquals("Invalid Input: mdoc_vp_token_signing_result->device_authentication->algorithm value cannot be empty or null", exception.message)
    }

}