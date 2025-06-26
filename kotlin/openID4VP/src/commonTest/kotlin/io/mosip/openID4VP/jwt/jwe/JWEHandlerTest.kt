package io.mosip.openID4VP.jwt.jwe

import com.nimbusds.jwt.EncryptedJWT
import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.jwt.jwe.encryption.EncryptionProvider
import io.mosip.openID4VP.testData.clientMetadataString
import kotlin.test.*

class JWEHandlerTest {

    private lateinit var clientMetadata: ClientMetadata
    private lateinit var jweHandler: JWEHandler
    private lateinit var publicKey: Jwk
    private val walletNonce = "wallet123"
    private val verifierNonce = "verifier456"

    @BeforeTest
    fun setUp() {
        clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataSerializer)
        publicKey = clientMetadata.jwks!!.keys[0]
        jweHandler = JWEHandler(
            clientMetadata.authorizationEncryptedResponseAlg!!,
            clientMetadata.authorizationEncryptedResponseEnc!!,
            publicKey,
            walletNonce,
            verifierNonce
        )

        mockkObject(Logger)
        every { Logger.error(any(), any(), any()) } answers { }
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should generate encrypted response successfully`() {
        val payload = mapOf("key1" to "value1", "key2" to 123)

        val encryptedResponse = jweHandler.generateEncryptedResponse(payload)

        assertNotNull(encryptedResponse)
        assertTrue(encryptedResponse.isNotEmpty())
        assertEquals(5, encryptedResponse.split(".").size)
    }



    @Test
    fun `should throw exception when encryption fails`() {
        val payload = mapOf("key1" to "value1")

        mockkObject(EncryptionProvider)
        every { EncryptionProvider.getEncrypter(any()) } throws Exception("Encryption failed")

        val exception = assertFailsWith<Exception> {
            jweHandler.generateEncryptedResponse(payload)
        }

        assertTrue(exception.message?.contains("Encryption failed") ?: false)
    }

    @Test
    fun `should throw exception when JWT encryption fails`() {
        val payload = mapOf("key1" to "value1")

        mockkConstructor(EncryptedJWT::class)
        every { anyConstructed<EncryptedJWT>().encrypt(any()) } throws Exception("JWT encryption failed")

        val exception = assertFailsWith<Exception> {
            jweHandler.generateEncryptedResponse(payload)
        }

        assertEquals("JWE Encryption failed", exception.message)

        verify {
            anyConstructed<EncryptedJWT>().encrypt(any())
        }

        verify {
            Logger.handleException(
                exceptionType = "JweEncryptionFailure",
                message = any(),
                className = "JWEHandler"
            )
        }
    }
}
