//package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp
//
//import android.util.Log
//import io.mockk.clearAllMocks
//import io.mockk.every
//import io.mockk.mockkStatic
//import io.mosip.openID4VP.common.convertJsonToMap
//import io.mosip.openID4VP.common.encodeToJsonString
//import io.mosip.openID4VP.exceptions.Exceptions
//import io.mosip.openID4VP.testData.ldpCredential1
//import io.mosip.openID4VP.testData.ldpCredential2
//import org.junit.After
//import org.junit.Assert.assertEquals
//import org.junit.Assert.assertNotNull
//import org.junit.Before
//import org.junit.Test
//import org.junit.jupiter.api.assertThrows
//
//class UnsignedLdpVPTokenBuilderTest {
//
//    private val verifiableCredentials = listOf(ldpCredential1, ldpCredential2)
//    private val id = "649d581c-f291-4969-9cd5-2c27385a348f"
//    private val holder = "did:example:123456789"
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
//    }
//
//    @After
//    fun tearDown() {
//        clearAllMocks()
//    }
//
//    @Test
//    fun `should create UnsignedLdpVPToken with valid input`() {
//        val result = UnsignedLdpVPTokenBuilder(
//            verifiableCredentials,
//            id,
//            holder
//        ).build() as UnsignedLdpVPToken
//
//        assertNotNull(result)
//        assertEquals(listOf("https://www.w3.org/2018/credentials/v1"), result.context)
//        assertEquals(listOf("VerifiablePresentation"), result.type)
//        assertEquals(verifiableCredentials, result.verifiableCredential)
//        assertEquals(id, result.id)
//        assertEquals(holder, result.holder)
//    }
//
//    @Test
//    fun `should return correct JSON representation`() {
//        val verifiableCredentials = listOf(ldpCredential1)
//        val token = UnsignedLdpVPTokenBuilder(
//            verifiableCredentials,
//            id,
//            holder
//        ).build() as UnsignedLdpVPToken
//
//        val expectedJson =
//            "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"type\":[\"VerifiablePresentation\"],\"verifiableCredential\":[{\"id\":\"did:rcw:38d51ff1-c55d-40be-af56-c3f30aaa81d4\",\"type\":[\"VerifiableCredential\",\"InsuranceCredential\"],\"proof\":{\"type\":\"Ed25519Signature2020\",\"created\":\"2025-05-12T10:51:03Z\",\"proofValue\":\"z62rZ8pWHi1PmkGYzZmgF8sQoLCPwwfvXYmSsC7P6KoaVyAoDv1SRi1VomcQqSv41HvkHKrHUfpJX3K3ZU9G1rVoh\",\"proofPurpose\":\"assertionMethod\",\"verificationMethod\":\"did:web:api.collab.mosip.net:identity-service:56de166e-0e2f-4734-b8e7-be42b3117d39#key-0\"},\"issuer\":\"did:web:api.collab.mosip.net:identity-service:56de166e-0e2f-4734-b8e7-be42b3117d39\",\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://holashchand.github.io/test_project/insurance-context.json\",\"https://w3id.org/security/suites/ed25519-2020/v1\"],\"issuanceDate\":\"2025-05-12T10:51:02.820Z\",\"expirationDate\":\"2025-06-11T10:51:02.814Z\",\"credentialSubject\":{\"id\":\"did:jwk:eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsInVzZSI6InNpZyIsImtpZCI6Ii1zUVpsbDhYQXBySGVlNG5CdzB5TUwtLTdsOFJBNGhaM2dMclkzMzdtVUUiLCJhbGciOiJSUzI1NiIsIm4iOiJrUHllWHdIMVM3cjE3WmhOMkl3YmhZejR6bnNEVnl3bDdLRzllUjZ3bUM1YUtaZ0dyY18yWXB1V28tT2RuWDhOc3VWLWFzU0NjU01FVThVdUZqNWtienhRRGdPWFNQWlI1MHVCS19TVEtXTHNVenVlRHpQZUpGdDhibWItVjgtQ0FOa2JrSGRYbXVSS0pUU0JVd3lWRXdtTERnb0ZLYTlVLXhjVTVELWFDcHJFVS1fQ1oyUGZDcF9jdmtJNmdOS2FKRHJBcVVlUkVQYzAzbl93WXd0bE82S1RhQ25jc0JMbEp2U1NBM1B1ZEN5ZFFMVUZwak12R2d3VUlFNkg3d3FoTGdZeXZLTVBTYzVEMG8ybWZ0cHNTVFNrY3p2OEVPdnMtNU5kaHZXTXFlc0dtSE5helk5bDhOMFQyWGxrM0ZqM1lDcXNmQ1lnLUd1RkFRaXpZOU1ZV3cifQ==\",\"dob\":\"2025-01-01\",\"email\":\"abcd@gmail.com\",\"gender\":\"Male\",\"mobile\":\"0123456789\",\"benefits\":[\"Critical Surgery\",\"Full body checkup\"],\"fullName\":\"wallet\",\"policyName\":\"wallet\",\"policyNumber\":\"5555\",\"policyIssuedOn\":\"2023-04-20\",\"policyExpiresOn\":\"2033-04-20\"}}],\"id\":\"649d581c-f291-4969-9cd5-2c27385a348f\",\"holder\":\"did:example:123456789\"}"
//        assertEquals(
//            expectedJson,
//            encodeToJsonString<UnsignedLdpVPToken>(token, "token", "UnsignedLdpVPToken")
//        )
//    }
//}

package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp

import io.mockk.every
import io.mockk.mockkObject
import io.mockk.unmockkAll
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPToken
import io.mosip.openID4VP.common.DateUtil
import io.mosip.openID4VP.common.URDNA2015Canonicalization
import io.mosip.openID4VP.constants.SignatureAlgorithm
import io.mosip.openID4VP.testData.ldpCredential1
import io.mosip.openID4VP.testData.ldpCredential2
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test

class UnsignedLdpVPTokenBuilderTest {

    private val verifiableCredentials = listOf(ldpCredential1, ldpCredential2)
    private val id = "649d581c-f291-4969-9cd5-2c27385a348f"
    private val holder = "did:example:123456789"
    private val challenge = "test-challenge"
    private val domain = "test-domain.com"
    private val mockDateTime = "2023-01-01T12:00:00Z"
    private val mockCanonicalizedData = "canonicalized-data"

    @Before
    fun setup() {
        mockkObject(DateUtil)
        every { DateUtil.formattedCurrentDateTime() } returns mockDateTime

        mockkObject(URDNA2015Canonicalization)
        every { URDNA2015Canonicalization.canonicalize(any()) } returns mockCanonicalizedData
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `test build with Ed25519Signature2020`() {
        // Arrange
        val builder = UnsignedLdpVPTokenBuilder(
            verifiableCredential = verifiableCredentials,
            id = id,
            holder = holder,
            challenge = challenge,
            domain = domain,
            signatureSuite = SignatureAlgorithm.Ed25519Signature2020.value
        )

        // Act
        val result = builder.build()

        // Assert
        Assert.assertNotNull(result)
        Assert.assertTrue(result.containsKey("vpTokenSigningPayload"))
        Assert.assertTrue(result.containsKey("unsignedVPToken"))

        val payload = result["vpTokenSigningPayload"] as LdpVPToken
        Assert.assertEquals(2, payload.context.size)
        Assert.assertTrue(payload.context.contains("https://www.w3.org/2018/credentials/v1"))
        Assert.assertTrue(payload.context.contains("https://w3id.org/security/suites/ed25519-2020/v1"))
        Assert.assertEquals(listOf("VerifiablePresentation"), payload.type)
        Assert.assertEquals(verifiableCredentials, payload.verifiableCredential)
        Assert.assertEquals(id, payload.id)
        Assert.assertEquals(holder, payload.holder)

        val proof = payload.proof
        Assert.assertNotNull(proof)
        Assert.assertEquals(SignatureAlgorithm.Ed25519Signature2020.value, proof?.type)
        Assert.assertEquals(mockDateTime, proof?.created)
        Assert.assertEquals(holder, proof?.verificationMethod)
        Assert.assertEquals(domain, proof?.domain)
        Assert.assertEquals(challenge, proof?.challenge)

        val unsignedToken = result["unsignedVPToken"] as UnsignedLdpVPToken
        Assert.assertEquals(mockCanonicalizedData, unsignedToken.dataToSign)
    }

    @Test
    fun `test build with JsonWebSignature2020`() {
        // Arrange
        val builder = UnsignedLdpVPTokenBuilder(
            verifiableCredential = verifiableCredentials,
            id = id,
            holder = holder,
            challenge = challenge,
            domain = domain,
            signatureSuite = SignatureAlgorithm.JsonWebSignature2020.value
        )

        // Act
        val result = builder.build()

        // Assert
        Assert.assertNotNull(result)

        val payload = result["vpTokenSigningPayload"] as LdpVPToken
        Assert.assertEquals(2, payload.context.size)
        Assert.assertTrue(payload.context.contains("https://www.w3.org/2018/credentials/v1"))
        Assert.assertTrue(payload.context.contains("https://w3id.org/security/suites/jws-2020/v1"))

        val proof = payload.proof
        Assert.assertNotNull(proof)
        Assert.assertEquals(SignatureAlgorithm.JsonWebSignature2020.value, proof?.type)
    }

    @Test
    fun `test build with unknown signature suite`() {
        // Arrange
        val unknownSignatureSuite = "UnknownSignatureSuite"
        val builder = UnsignedLdpVPTokenBuilder(
            verifiableCredential = verifiableCredentials,
            id = id,
            holder = holder,
            challenge = challenge,
            domain = domain,
            signatureSuite = unknownSignatureSuite
        )

        // Act
        val result = builder.build()

        // Assert
        Assert.assertNotNull(result)

        val payload = result["vpTokenSigningPayload"] as LdpVPToken
        Assert.assertEquals(1, payload.context.size)
        Assert.assertTrue(payload.context.contains("https://www.w3.org/2018/credentials/v1"))

        val proof = payload.proof
        Assert.assertNotNull(proof)
        Assert.assertEquals(unknownSignatureSuite, proof?.type)
    }

    @Test
    fun `test build with empty verifiable credential list`() {
        // Arrange
        val builder = UnsignedLdpVPTokenBuilder(
            verifiableCredential = emptyList(),
            id = id,
            holder = holder,
            challenge = challenge,
            domain = domain,
            signatureSuite = SignatureAlgorithm.Ed25519Signature2020.value
        )

        // Act
        val result = builder.build()

        // Assert
        Assert.assertNotNull(result)

        val payload = result["vpTokenSigningPayload"] as LdpVPToken
        Assert.assertTrue(payload.verifiableCredential.isEmpty())
    }

    @Test
    fun `test canonicalization error handling`() {
        // Arrange
        every { URDNA2015Canonicalization.canonicalize(any()) } throws RuntimeException("Canonicalization failed")

        val builder = UnsignedLdpVPTokenBuilder(
            verifiableCredential = verifiableCredentials,
            id = id,
            holder = holder,
            challenge = challenge,
            domain = domain,
            signatureSuite = SignatureAlgorithm.Ed25519Signature2020.value
        )

        // Act & Assert
        val exception = Assert.assertThrows(RuntimeException::class.java) {
            builder.build()
        }
        Assert.assertEquals("Canonicalization failed", exception.message)
    }
}
