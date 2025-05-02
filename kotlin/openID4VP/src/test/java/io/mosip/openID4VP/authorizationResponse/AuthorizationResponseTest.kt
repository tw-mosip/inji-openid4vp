package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.testData.*
import org.junit.Assert.assertEquals
import org.junit.Test

class AuthorizationResponseTest {
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