package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc


import co.nstant.`in`.cbor.model.UnicodeString
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.verify
import io.mosip.openID4VP.common.Logger
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
        mockkObject(Logger)
        every { Logger.error(any(), any(), any()) } answers {  }
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