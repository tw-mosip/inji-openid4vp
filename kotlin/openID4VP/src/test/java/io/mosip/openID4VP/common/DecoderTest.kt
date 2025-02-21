package io.mosip.openID4VP.common

import android.os.Build
import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mosip.openID4VP.common.BuildConfig.isAndroid
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Assertions.assertTrue

class DecoderTest {

    @Before
    fun setUp() {
        mockkObject(BuildConfig)
        mockkStatic(android.util.Base64::class)
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
    fun `should decode the base64 url encoded content successfully`() {
        every { isAndroid() } returns false
        val decodedContent = Decoder.decodeBase64Data("aGVsbG8gd29ybGQ=")
       assertEquals("hello world", decodedContent.toString(Charsets.UTF_8))
    }

    @Test
    fun `should throw error when given base64 url encoded data contains non base64 character`() {
        every { isAndroid() } returns false
        val exception = Assertions.assertThrows(IllegalArgumentException::class.java) {
            Decoder.decodeBase64Data("aGVsbG8%d29ybGQ=")
        }

        Assertions.assertEquals(
            "Illegal base64 character 25",
            exception.message
        )
    }

    @Test
    fun `should throw error when given base64 url encoded data has truncated bytes`() {
        every { isAndroid() } returns false
        val exception = Assertions.assertThrows(IllegalArgumentException::class.java) {
            Decoder.decodeBase64Data("aGVsbG8gd29ybG=")
        }

        Assertions.assertEquals(
            "Input byte array has wrong 4-byte ending unit",
            exception.message
        )
    }

    @Test
    fun `should decode the base64 url encoded content successfully with API greater than or equal to Version O`() {
        every { BuildConfig.getVersionSDKInt() } returns Build.VERSION_CODES.O
        every { isAndroid() } returns true

        val decodedData: ByteArray = Decoder.decodeBase64Data("aGVsbG8gd29ybGQ")

        assertTrue("hello world".toByteArray().contentEquals(decodedData))
    }

    @Test
    fun `should decode the base64 url encoded content successfully with API lesser than  Version O`() {

        every { BuildConfig.getVersionSDKInt() } returns Build.VERSION_CODES.N
        every { isAndroid() } returns true
        every {
            android.util.Base64.decode(
                "aGVsbG8gd29ybGQ=",
                android.util.Base64.DEFAULT
            )
        } returns "hello world".toByteArray()

        val decodedData: ByteArray = Decoder.decodeBase64Data("aGVsbG8gd29ybGQ")

        Assertions.assertEquals("hello world", decodedData.toString(Charsets.UTF_8))
    }
}
