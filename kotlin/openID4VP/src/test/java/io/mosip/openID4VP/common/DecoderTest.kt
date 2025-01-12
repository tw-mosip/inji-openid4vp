package io.mosip.openID4VP.common

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

class DecoderTest {

    @Before
    fun setUp() {
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
    fun `should throw invalid input exception for empty input`() {
        val encodedData = ""
        val expectedExceptionMessage = "Invalid Input: encoded data value cannot be an empty string, null, or an integer"

        val actualException =
            assertThrows(AuthorizationRequestExceptions.InvalidInput::class.java) {
                Decoder.decodeBase64ToString(encodedData)
            }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should decode valid Base64 string`() {
        val encodedData = "SGVsbG8gV29ybGQ="
        val expectedDecodedString = "Hello World"

        val decodedString = Decoder.decodeBase64ToString(encodedData)

        assertEquals(expectedDecodedString, decodedString)
    }
}