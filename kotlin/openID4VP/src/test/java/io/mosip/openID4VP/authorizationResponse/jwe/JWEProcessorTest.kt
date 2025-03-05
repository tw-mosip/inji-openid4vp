
package io.mosip.openID4VP.authorizationResponse.jwe

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.testData.clientMetadataString
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue

class JWEProcessorTest {

    private lateinit var clientMetadata: ClientMetadata
    private lateinit var jweProcessor: JWEProcessor

    @Before
    fun setUp() {
        clientMetadata = deserializeAndValidate(clientMetadataString, ClientMetadataSerializer)
        jweProcessor = JWEProcessor(clientMetadata)
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
    fun `should generate encrypted response successfully`() {
        val payload = mapOf("key1" to "value1", "key2" to 123)

        val encryptedResponse = jweProcessor.generateEncryptedResponse(payload)

        assertNotNull(encryptedResponse)
        assert(encryptedResponse.isNotEmpty())
        assertTrue(encryptedResponse.split(".").size == 5)
    }
}
