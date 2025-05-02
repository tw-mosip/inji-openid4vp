package io.mosip.openID4VP.authorizationResponse.models.unsignedVPToken.types

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.UnsignedMdocVPToken
import io.mosip.openID4VP.exceptions.Exceptions.InvalidData
import io.mosip.openID4VP.testData.mdocCredential
import io.mosip.openID4VP.testData.responseUrl
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test


class UnsignedMdocVPTokenTest {

    private val clientId = "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs"
    private val responseUri = responseUrl
    private val verifierNonce = "GM12ZywLxmA0PjQFevb/WQ=="
    private val walletNonce = "P0RVGUe5OoDctvuK"

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.e(any(), any()) } answers {
            val tag = arg<String>(0)
            val msg = arg<String>(1)
            println("Error: logTag: $tag | Message: $msg")
            0
        }
        every { Log.d(any(), any()) } answers {
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
    fun `should create UnsignedMdocVPToken with valid input`() {
        val mdocCredentials = listOf(mdocCredential)

        val result = UnsignedMdocVPToken.build(
            mdocCredentials,
            clientId,
            responseUri,
            verifierNonce,
            walletNonce
        )

        assertNotNull(result)
        assertTrue(result.unsignedDeviceAuth.isNotEmpty())
        assertEquals(1, result.unsignedDeviceAuth.size)
    }

    @Test
    fun `should throw exception when duplicate docType is found`() {
        val mdocCredentials = listOf(mdocCredential, mdocCredential)

        val actualException =
            assertThrows(InvalidData::class.java) {
                UnsignedMdocVPToken.build(
                    mdocCredentials,
                    clientId,
                    responseUri,
                    verifierNonce,
                    walletNonce
                )
            }

       assertEquals("Duplicate Mdoc Credentials with same doctype found", actualException.message)
    }

}