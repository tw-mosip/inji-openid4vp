package io.mosip.openID4VP.authorizationResponse.authenticationContainer.types.mdoc

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.verify
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.*

class MdocAuthenticationContainerTest {

    private lateinit var mockDeviceAuthentication1: DeviceAuthentication
    private lateinit var mockDeviceAuthentication2: DeviceAuthentication
    private lateinit var deviceAuthenticationMap: Map<String, DeviceAuthentication>

    @Before
    fun setUp() {
        mockDeviceAuthentication1 = mockk(relaxed = true)
        mockDeviceAuthentication2 = mockk(relaxed = true)
        deviceAuthenticationMap = mapOf(
            "doctype1" to mockDeviceAuthentication1,
            "doctype2" to mockDeviceAuthentication2
        )
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
    fun `should call validate on each device authentication in map`() {
        val mdocAuthenticationContainer = MdocAuthenticationContainer(deviceAuthenticationMap)
        mdocAuthenticationContainer.validate()
        verify { mockDeviceAuthentication1.validate() }
        verify { mockDeviceAuthentication2.validate() }
    }

    @Test
    fun `should handle empty map`() {
        val emptyMap = emptyMap<String, DeviceAuthentication>()
        val mdocAuthenticationContainer = MdocAuthenticationContainer(emptyMap)
        assertDoesNotThrow { mdocAuthenticationContainer.validate() }
    }

}