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
