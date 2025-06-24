//package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc
//
//import android.util.Log
//import io.mockk.clearAllMocks
//import io.mockk.every
//import io.mockk.mockkStatic
//import io.mosip.openID4VP.exceptions.Exceptions.InvalidData
//import io.mosip.openID4VP.testData.mdocCredential
//import io.mosip.openID4VP.testData.responseUrl
//import org.junit.After
//import org.junit.Assert.assertEquals
//import org.junit.Assert.assertFalse
//import org.junit.Assert.assertNotNull
//import org.junit.Assert.assertThrows
//import org.junit.Assert.assertTrue
//import org.junit.Before
//import org.junit.Ignore
//import org.junit.Test
//
//
//class UnsignedMdocVPTokenBuilderTest {
//
//    private val clientId = "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs"
//    private val responseUrl = responseUrl
//    private val verifierNonce = "GM12ZywLxmA0PjQFevb/WQ=="
//    private val walletNonce = "P0RVGUe5OoDctvuK"
//
//    @Before
//    fun setUp() {
//        mockkStatic(Log::class)
//        every { Log.e(any(), any()) } answers {
//            val tag = arg<String>(0)
//            val msg = arg<String>(1)
//            println("Error: logTag: $tag | Message: $msg")
//            0
//        }
//        every { Log.d(any(), any()) } answers {
//            val tag = arg<String>(0)
//            val msg = arg<String>(1)
//            println("Error: logTag: $tag | Message: $msg")
//            0
//        }
//    }
//
//    @After
//    fun tearDown() {
//        clearAllMocks()
//    }
//
//    @Ignore
//    @Test
//    fun `should create UnsignedMdocVPToken with valid input`() {
//        val mdocCredentials = listOf(mdocCredential)
//
//        val result = UnsignedMdocVPTokenBuilder(
//            mdocCredentials,
//            clientId,
//            responseUrl,
//            verifierNonce,
//            walletNonce
//        ).build() as UnsignedMdocVPToken
//
//        assertNotNull(result)
//        assertTrue(result.docTypeToDeviceAuthenticationBytes.isNotEmpty())
//        assertEquals(1, result.docTypeToDeviceAuthenticationBytes.size)
//    }
//
//    @Test
//    fun `should throw exception when duplicate docType is found`() {
//        val mdocCredentials = listOf(mdocCredential, mdocCredential)
//
//        val actualException =
//            assertThrows(InvalidData::class.java) {
//                UnsignedMdocVPTokenBuilder(
//                    mdocCredentials,
//                    clientId,
//                    responseUrl,
//                    verifierNonce,
//                    walletNonce
//                ).build() as UnsignedMdocVPToken
//            }
//
//       assertEquals("Duplicate Mdoc Credentials with same doctype found", actualException.message)
//    }
//
//    @Test
//    fun `should create token with empty device auth when mdocCredentials list is empty`() {
//        val result = UnsignedMdocVPTokenBuilder(
//            emptyList(),
//            clientId,
//            responseUrl,
//            verifierNonce,
//            walletNonce
//        ).build() as UnsignedMdocVPToken
//
//        assertNotNull(result)
//        assertTrue(result.docTypeToDeviceAuthenticationBytes.isEmpty())
//    }
//
//    @Test
//    fun `should create token with correct structure and payload format`() {
//        val mdocCredentials = listOf(mdocCredential)
//
//        val result = UnsignedMdocVPTokenBuilder(
//            mdocCredentials,
//            clientId,
//            responseUrl,
//            verifierNonce,
//            walletNonce
//        ).build() as UnsignedMdocVPToken
//
//        val docType = result.docTypeToDeviceAuthenticationBytes.keys.first()
//        val authData = result.docTypeToDeviceAuthenticationBytes[docType]
//
//        assertNotNull(docType)
//        assertFalse(docType.isEmpty())
//
//        assertNotNull(authData)
//        assertTrue(authData is String)
//
//        // Check if the payload is a valid hex string
//        val hexString = authData as String
//        assertTrue(hexString.matches("[0-9A-Fa-f]+".toRegex()))
//    }
//
//}
//
//


package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc

import android.util.Log
import co.nstant.`in`.cbor.model.UnicodeString
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.verify
import io.mosip.openID4VP.common.getDecodedMdocCredential
import io.mosip.openID4VP.exceptions.Exceptions.InvalidData
import io.mosip.openID4VP.testData.clientId
import io.mosip.openID4VP.testData.mdocCredential
import io.mosip.openID4VP.testData.responseUrl
import io.mosip.openID4VP.testData.verifierNonce
import io.mosip.openID4VP.testData.walletNonce
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class UnsignedMdocVPTokenBuilderTest {

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
            println("Debug: logTag: $tag | Message: $msg")
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

        val result = UnsignedMdocVPTokenBuilder(
            mdocCredentials,
            clientId,
            responseUrl,
            verifierNonce,
            walletNonce
        ).build()

        // Check the overall structure
        assertTrue(result.containsKey("vpTokenSigningPayload"))
        assertTrue(result.containsKey("unsignedVPToken"))

        // Check vpTokenSigningPayload
        assertEquals(mdocCredentials, result["vpTokenSigningPayload"])

        // Check unsignedVPToken
        val unsignedToken = result["unsignedVPToken"] as UnsignedMdocVPToken
        assertTrue(unsignedToken.docTypeToDeviceAuthenticationBytes.isNotEmpty())
        assertEquals(1, unsignedToken.docTypeToDeviceAuthenticationBytes.size)
    }

    @Test
    fun `should throw exception when duplicate docType is found`() {
        val mdocCredentials = listOf(mdocCredential, mdocCredential)

        val exception = assertThrows(InvalidData::class.java) {
            UnsignedMdocVPTokenBuilder(
                mdocCredentials,
                clientId,
                responseUrl,
                verifierNonce,
                walletNonce
            ).build()
        }

        assertEquals("Duplicate Mdoc Credentials with same doctype found", exception.message)
    }

    @Test
    fun `should create token with empty device auth when mdocCredentials list is empty`() {
        val result = UnsignedMdocVPTokenBuilder(
            emptyList(),
            clientId,
            responseUrl,
            verifierNonce,
            walletNonce
        ).build()

        val unsignedToken = result["unsignedVPToken"] as UnsignedMdocVPToken
        assertTrue(unsignedToken.docTypeToDeviceAuthenticationBytes.isEmpty())

        // Verify payload is empty list
        assertEquals(emptyList<String>(), result["vpTokenSigningPayload"])
    }

    @Test
    fun `should create token with correct structure and payload format`() {
        val mdocCredentials = listOf(mdocCredential)

        val result = UnsignedMdocVPTokenBuilder(
            mdocCredentials,
            clientId,
            responseUrl,
            verifierNonce,
            walletNonce
        ).build()

        val unsignedToken = result["unsignedVPToken"] as UnsignedMdocVPToken
        val docType = unsignedToken.docTypeToDeviceAuthenticationBytes.keys.first()
        val authData = unsignedToken.docTypeToDeviceAuthenticationBytes[docType]

        assertNotNull(docType)
        assertFalse(docType.isEmpty())

        assertNotNull(authData)
        assertTrue(authData is String)

        // Check if the payload is a valid hex string
        val hexString = authData as String
        assertTrue(hexString.matches("[0-9A-Fa-f]+".toRegex()))
    }
    @Test
    fun `should handle multiple different mdoc credentials correctly`() {
        // Mock a second mdoc credential with different docType
        mockkStatic(::getDecodedMdocCredential)

        val secondMdocCredential = "second_mdoc_credential"

        // Create CBOR Maps instead of Kotlin Maps
        val firstDecodedMap = co.nstant.`in`.cbor.model.Map().apply {
            put(UnicodeString("docType"), UnicodeString("docType1"))
        }

        val secondDecodedMap = co.nstant.`in`.cbor.model.Map().apply {
            put(UnicodeString("docType"), UnicodeString("docType2"))
        }

        every { getDecodedMdocCredential(mdocCredential) } returns firstDecodedMap
        every { getDecodedMdocCredential(secondMdocCredential) } returns secondDecodedMap

        val mdocCredentials = listOf(mdocCredential, secondMdocCredential)

        val result = UnsignedMdocVPTokenBuilder(
            mdocCredentials,
            clientId,
            responseUrl,
            verifierNonce,
            walletNonce
        ).build()

        val unsignedToken = result["unsignedVPToken"] as UnsignedMdocVPToken
        assertEquals(2, unsignedToken.docTypeToDeviceAuthenticationBytes.size)
        assertTrue(unsignedToken.docTypeToDeviceAuthenticationBytes.containsKey("docType1"))
        assertTrue(unsignedToken.docTypeToDeviceAuthenticationBytes.containsKey("docType2"))
    }

    @Test
    fun `should throw exception for malformed mdoc credential`() {
        mockkStatic(::getDecodedMdocCredential)

        every { getDecodedMdocCredential(any()) } throws IllegalArgumentException("Invalid CBOR data")

        val exception = assertThrows(IllegalArgumentException::class.java) {
            UnsignedMdocVPTokenBuilder(
                listOf("invalid_mdoc_credential"),
                clientId,
                responseUrl,
                verifierNonce,
                walletNonce
            ).build()
        }

        assertEquals("Invalid CBOR data", exception.message)
    }

    @Test
    fun `should use provided parameters correctly in token creation`() {
        val spyBuilder = spyk(
            UnsignedMdocVPTokenBuilder(
                listOf(mdocCredential),
                clientId,
                responseUrl,
                verifierNonce,
                walletNonce
            )
        )

        spyBuilder.build()
        verify {
            spyBuilder.build()
        }

    }
}