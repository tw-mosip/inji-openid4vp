package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.Proof
import io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc.MdocVPToken
import io.mosip.openID4VP.testData.*
import org.junit.Assert.assertEquals
import org.junit.Test

class AuthorizationResponseTest {

    private val ldpVPToken = LdpVPToken(
        context = listOf("context"),
        type = listOf("type"),
        verifiableCredential = listOf("VC1"),
        id = "id",
        holder = "holder",
        proof = Proof(
            type = "type",
            created = "time",
            challenge = "challenge",
            domain = "domain",
            jws = "eryy....ewr",
            proofPurpose = "authentication",
            verificationMethod = "did:example:holder#key-1"
        )
    )

    private val vpToken = VPTokenType.VPTokenElement(
        ldpVPToken
    )

    private val authorizationResponse = AuthorizationResponse(
        presentationSubmission = presentationSubmission,
        vpToken = vpToken,
        state = "state"
    )
    @Test
    fun `should create encodedJsonMap successfully`() {


        val encodedJsonMap = authorizationResponse.toJsonEncodedMap()

        assertEquals(
            mapOf(
                "presentation_submission" to "{\"id\":\"ps_id\",\"definition_id\":\"client_id\",\"descriptor_map\":[{\"id\":\"input_descriptor_1\",\"format\":\"ldp_vp\",\"path\":\"$\",\"path_nested\":{\"id\":\"input_descriptor_1\",\"format\":\"ldp_vp\",\"path\":\"$.verifiableCredential[0]\"}}]}",
                "vp_token" to "{\"@context\":[\"context\"],\"type\":[\"type\"],\"verifiableCredential\":[\"VC1\"],\"id\":\"id\",\"holder\":\"holder\",\"proof\":{\"type\":\"type\",\"created\":\"time\",\"challenge\":\"challenge\",\"domain\":\"domain\",\"jws\":\"eryy....ewr\",\"proofPurpose\":\"authentication\",\"verificationMethod\":\"did:example:holder#key-1\"}}",
                "state" to "state"
            ),
            encodedJsonMap
        )
    }

    @Test
    fun `should create encodedJsonMap with no nullable fields`() {
        val authorizationResponse = AuthorizationResponse(
            presentationSubmission = presentationSubmission,
            vpToken = vpToken,
            state = null
        )

        val encodedJsonMap = authorizationResponse.toJsonEncodedMap()

        assertEquals(
            mapOf(
                "presentation_submission" to "{\"id\":\"ps_id\",\"definition_id\":\"client_id\",\"descriptor_map\":[{\"id\":\"input_descriptor_1\",\"format\":\"ldp_vp\",\"path\":\"$\",\"path_nested\":{\"id\":\"input_descriptor_1\",\"format\":\"ldp_vp\",\"path\":\"$.verifiableCredential[0]\"}}]}",
                "vp_token" to "{\"@context\":[\"context\"],\"type\":[\"type\"],\"verifiableCredential\":[\"VC1\"],\"id\":\"id\",\"holder\":\"holder\",\"proof\":{\"type\":\"type\",\"created\":\"time\",\"challenge\":\"challenge\",\"domain\":\"domain\",\"jws\":\"eryy....ewr\",\"proofPurpose\":\"authentication\",\"verificationMethod\":\"did:example:holder#key-1\"}}"
            ),
            encodedJsonMap
        )
    }
}