package io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc

import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.exceptions.Exceptions.InvalidInput
import kotlin.test.*

class DeviceAuthenticationTest {

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
    fun `validate succeeds with valid inputs`() {
        val deviceAuth = DeviceAuthentication("testSignature", "SHA256withRSA")
        deviceAuth.validate() // Should not throw
    }

    @Test
    fun `validate throws exception with null signature string`() {
        val deviceAuth = DeviceAuthentication("null", "SHA256withRSA")

        val exception = assertFailsWith<InvalidInput> {
            deviceAuth.validate()
        }
        assertEquals(
            "Invalid Input: mdoc_vp_token_signing_result->device_authentication->signature value cannot be empty or null",
            exception.message
        )
    }

    @Test
    fun `validate throws exception with null algorithm string`() {
        val deviceAuth = DeviceAuthentication("testSignature", "null")

        val exception = assertFailsWith<InvalidInput> {
            deviceAuth.validate()
        }
        assertEquals(
            "Invalid Input: mdoc_vp_token_signing_result->device_authentication->algorithm value cannot be empty or null",
            exception.message
        )
    }
}
