package io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc

import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.Test
import org.junit.jupiter.api.Assertions.*


class MdocVPTokenTest {

    @Test
    fun `constructor creates valid MdocVPToken object`() {
        val base64Response = "dGhpcyBpcyBhIHRlc3QgYmFzZTY0IHN0cmluZw=="
        val token = MdocVPToken(base64Response)

        assertNotNull(token)
        assertEquals(base64Response, token.base64EncodedDeviceResponse)
    }

    @Test
    fun `serializer should output base64EncodedDeviceResponse as string`() {
        val base64Response = "dGhpcyBpcyBhIHRlc3QgYmFzZTY0IHN0cmluZw=="
        val token = MdocVPToken(base64Response)

        val objectMapper = ObjectMapper()
        val serializedJson = objectMapper.writeValueAsString(token)

        assertEquals("\"dGhpcyBpcyBhIHRlc3QgYmFzZTY0IHN0cmluZw==\"", serializedJson)
    }

}