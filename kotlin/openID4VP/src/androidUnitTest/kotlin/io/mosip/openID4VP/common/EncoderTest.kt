package io.mosip.openID4VP.common

import android.os.Build
import android.util.Base64
import android.util.Base64.encodeToString
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mosip.vercred.vcverifier.utils.BuildConfig.getVersionSDKInt
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals


class EncoderTest {

    @BeforeTest
    fun setUp() {
        mockkStatic(Base64::class)
        mockkObject(BuildConfig)
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should encode using android Base64 when API level is below VERSION_O`() {
        every { getVersionSDKInt() } returns Build.VERSION_CODES.O - 1
        every {
            encodeToString("hello world".toByteArray(), any())
        } returns "aGVsbG8gd29ybGQ"

        val encodedData = encodeToBase64Url("hello world".toByteArray())

        assertEquals("aGVsbG8gd29ybGQ", encodedData)
    }

    @Test
    fun `should encode using Java Base64 when API level is VERSION_O or above`() {
        every { getVersionSDKInt() } returns Build.VERSION_CODES.O

        val encodedData = encodeToBase64Url("hello world".toByteArray())

        assertEquals("aGVsbG8gd29ybGQ", encodedData)
    }

    @Test
    fun `should encode empty byte array using android Base64 when API level is below VERSION_O`() {
        every { getVersionSDKInt() } returns Build.VERSION_CODES.O - 1
        every { encodeToString(ByteArray(0), any()) } returns ""

        val encodedData = encodeToBase64Url(ByteArray(0))

        assertEquals("", encodedData)
    }

    @Test
    fun `should encode empty byte array using Java Base64 when API level is VERSION_O or above`() {
        every { getVersionSDKInt() } returns Build.VERSION_CODES.O

        val encodedData = encodeToBase64Url(ByteArray(0))

        assertEquals("", encodedData)
    }
}
