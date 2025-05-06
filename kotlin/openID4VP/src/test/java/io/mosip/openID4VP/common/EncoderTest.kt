package io.mosip.openID4VP.common

import android.os.Build
import android.util.Base64.encodeToString
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

class EncoderTest {

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
    fun `should encode the content to base64 url successfully`() {
        every { isAndroid() } returns false
        val encodedContent = Encoder.encodeToBase64Url("hello world".toByteArray())
        assertEquals("aGVsbG8gd29ybGQ=", encodedContent)
    }

    @Test
    fun `should handle empty byte array properly`() {
        every { isAndroid() } returns false
        val encodedContent = Encoder.encodeToBase64Url(ByteArray(0))
        assertEquals("", encodedContent)
    }

    @Test
    fun `should encode the content to base64 url successfully with API greater than or equal to Version O`() {
        every { BuildConfig.getVersionSDKInt() } returns Build.VERSION_CODES.O
        every { isAndroid() } returns true

        val encodedData = Encoder.encodeToBase64Url("hello world".toByteArray())

        assertEquals("aGVsbG8gd29ybGQ=", encodedData)
    }

    @Test
    fun `should encode the content to base64 url successfully with API lesser than Version O`() {
        every { BuildConfig.getVersionSDKInt() } returns Build.VERSION_CODES.N
        every { isAndroid() } returns true
        every {
            encodeToString(
                "hello world".toByteArray(),
                any()
            )
        } returns "aGVsbG8gd29ybGQ="

        val encodedData = Encoder.encodeToBase64Url("hello world".toByteArray())

        assertEquals("aGVsbG8gd29ybGQ=", encodedData)
    }

    @Test
    fun `should handle special characters correctly during encoding`() {
        every { isAndroid() } returns false
        val specialChars = "!@#$%^&*()_+{}[]|\":<>?,./"
        val encodedContent = Encoder.encodeToBase64Url(specialChars.toByteArray())
        val decodedContent = Decoder.decodeBase64Data(encodedContent)
        assertEquals(specialChars, decodedContent.toString(Charsets.UTF_8))
    }
}