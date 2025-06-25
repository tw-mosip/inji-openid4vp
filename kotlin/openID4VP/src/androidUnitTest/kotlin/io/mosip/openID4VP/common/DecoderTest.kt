package io.mosip.openID4VP.common


import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Assertions.assertTrue

class DecoderTest {

    @Before
    fun setUp() {
        mockkStatic(android.util.Base64::class)
        mockkObject(Logger)
        every { Logger.error(any(), any(), any()) } answers {  }
    }

    @After
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should decode the base64 url encoded content successfully with API greater than or equal to Version O`() {

        val decodedData: ByteArray = decodeBase64Data("aGVsbG8gd29ybGQ")

        assertTrue("hello world".toByteArray().contentEquals(decodedData))
    }

    @Test
    fun `should decode the base64 url encoded content successfully with API lesser than  Version O`() {

        every {
            android.util.Base64.decode(
                "aGVsbG8gd29ybGQ=",
                android.util.Base64.DEFAULT
            )
        } returns "hello world".toByteArray()

        val decodedData: ByteArray = decodeBase64Data("aGVsbG8gd29ybGQ")

        Assertions.assertEquals("hello world", decodedData.toString(Charsets.UTF_8))
    }
}
