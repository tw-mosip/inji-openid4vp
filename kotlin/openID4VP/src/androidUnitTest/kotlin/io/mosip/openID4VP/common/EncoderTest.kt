package io.mosip.openID4VP.common


import android.util.Base64.encodeToString

import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

class EncoderTest {

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
    fun `should encode the content to base64 url successfully with API greater than or equal to Version O`() {

        val encodedData = encodeToBase64Url("hello world".toByteArray())

        assertEquals("aGVsbG8gd29ybGQ=", encodedData)
    }

    @Test
    fun `should encode the content to base64 url successfully with API lesser than Version O`() {
        every {
            encodeToString(
                "hello world".toByteArray(),
                any()
            )
        } returns "aGVsbG8gd29ybGQ="

        val encodedData = encodeToBase64Url("hello world".toByteArray())

        assertEquals("aGVsbG8gd29ybGQ=", encodedData)
    }

}