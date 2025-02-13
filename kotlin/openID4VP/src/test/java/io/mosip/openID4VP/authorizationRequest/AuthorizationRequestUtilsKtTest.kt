package io.mosip.openID4VP.authorizationRequest

import org.junit.Assert.*
import org.junit.Test

class AuthorizationRequestUtilsKtTest {
    @Test
    fun testExtractClientIdPartOnlyWithDIDClientId() {
        val clientIdWithDidScheme = "did:example:123#1"

        val result = extractClientIdPartOnly(clientIdWithDidScheme)

        assertEquals(result, "did:example:123#1")
    }

    @Test
    fun testExtractClientIdPartOnlyWithRedirectUriClientId() {
        val clientIdWithRedirectUriScheme = "redirect_uri:https://client.example.org/cb"

        val result = extractClientIdPartOnly(clientIdWithRedirectUriScheme)

        assertEquals(result, "https://client.example.org/cb")
    }

    @Test
    fun testExtractClientIdPartOnlyWithPreRegisteredClientId() {
        val clientIdWithPreRegisteredSchemeWithoutSchemeMentioned = "example-client"

        val originalClientIdentifier = extractClientIdPartOnly(clientIdWithPreRegisteredSchemeWithoutSchemeMentioned)

        assertEquals(originalClientIdentifier, "example-client")
    }

    @Test
    fun testClientIdExtractionWithNoColonCharacterPresentInClientId() {
        val clientId = "mock-client"

        val clientIdScheme = extractClientIdScheme(clientId)

        assertEquals(clientIdScheme, "pre-registered")
    }

    @Test
    fun testClientIdExtractionWithDidScheme() {
        val clientIdWithDidScheme = "did:example:123#1"

        val clientIdScheme = extractClientIdScheme(clientIdWithDidScheme)

        assertEquals(clientIdScheme, "did")
    }
}