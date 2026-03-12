package io.mosip.openID4VP.common

import android.os.Build
import android.util.Base64
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class DecoderTest {

    @BeforeTest
    fun setUp() {
        mockkStatic(Base64::class)
        mockkObject(BuildConfig)

        every {
            Base64.decode(any<String>(), any<Int>())
        } answers {
            ByteArray(0)
        }
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should decode base64 url safe content using android Base64 when API level is below VERSION_O`() {
        every { BuildConfig.getVersionSDKInt() } returns Build.VERSION_CODES.O - 1
        val input = "aGVsbG8gd29ybGQ="
        val expectedOutput = "hello world"

        every {
            Base64.decode(input, Base64.DEFAULT or Base64.URL_SAFE)
        } answers {
            expectedOutput.toByteArray()
        }

        val result = decodeFromBase64Url(input)

        assertEquals(expectedOutput, result.toString(Charsets.UTF_8))
    }

    @Test
    fun `should decode base64 url safe content using Java Base64 when API level is VERSION_O or above`() {
        every { BuildConfig.getVersionSDKInt() } returns Build.VERSION_CODES.O
        val input = "aGVsbG8gd29ybGQ"

        val result = decodeFromBase64Url(input)

        assertEquals("hello world", result.toString(Charsets.UTF_8))
    }

    @Test
    fun `should handle url safe characters using android Base64 when API level is below VERSION_O`() {
        every { BuildConfig.getVersionSDKInt() } returns Build.VERSION_CODES.O - 1
        val input = "aGVsbG8-d29ybGQ_"
        val expectedOutput = "hello>world?"

        every {
            Base64.decode(input, Base64.DEFAULT or Base64.URL_SAFE)
        } answers {
            expectedOutput.toByteArray()
        }

        val result = decodeFromBase64Url(input)

        assertEquals(expectedOutput, result.toString(Charsets.UTF_8))
    }

    @Test
    fun `should throw error for invalid base64 using android Base64 when API level is below VERSION_O`() {
        every { BuildConfig.getVersionSDKInt() } returns Build.VERSION_CODES.O - 1
        val input = "invalid%%base64"

        every {
            Base64.decode(input, Base64.DEFAULT or Base64.URL_SAFE)
        } throws IllegalArgumentException("Invalid base64")

        assertFailsWith<IllegalArgumentException> {
            decodeFromBase64Url(input)
        }
    }

    @Test
    fun `should throw error for invalid base64 using Java Base64 when API level is VERSION_O or above`() {
        every { BuildConfig.getVersionSDKInt() } returns Build.VERSION_CODES.O
        val input = "invalid%%base64"

        assertFailsWith<IllegalArgumentException> {
            decodeFromBase64Url(input)
        }
    }

    @Test
    fun `should decode empty string using android Base64 when API level is below VERSION_O`() {
        every { BuildConfig.getVersionSDKInt() } returns Build.VERSION_CODES.O - 1

        every {
            Base64.decode("", Base64.DEFAULT or Base64.URL_SAFE)
        } answers {
            ByteArray(0)
        }

        val result = decodeFromBase64Url("")

        assertEquals("", result.toString(Charsets.UTF_8))
    }

    @Test
    fun `should decode empty string using Java Base64 when API level is VERSION_O or above`() {
        every { BuildConfig.getVersionSDKInt() } returns Build.VERSION_CODES.O

        val result = decodeFromBase64Url("")

        assertEquals("", result.toString(Charsets.UTF_8))
    }
}
