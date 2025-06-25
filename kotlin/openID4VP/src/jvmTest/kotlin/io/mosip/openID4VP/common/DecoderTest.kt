package io.mosip.openID4VP.common

import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions

class DecoderTest {

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
    fun `should decode the base64 url encoded content successfully`() {
        val decodedContent = decodeBase64Data("aGVsbG8gd29ybGQ=")
        assertEquals("hello world", decodedContent.toString(Charsets.UTF_8))
    }

    @Test
    fun `should throw error when given base64 url encoded data contains non base64 character`() {
        val exception = Assertions.assertThrows(IllegalArgumentException::class.java) {
            decodeBase64Data("aGVsbG8%d29ybGQ=")
        }

        Assertions.assertEquals(
            "Illegal base64 character 25",
            exception.message
        )
    }

    @Test
    fun `should throw error when given base64 url encoded data has truncated bytes`() {
        val exception = Assertions.assertThrows(IllegalArgumentException::class.java) {
            decodeBase64Data("aGVsbG8gd29ybG=")
        }

        Assertions.assertEquals(
            "Input byte array has wrong 4-byte ending unit",
            exception.message
        )
    }

}
