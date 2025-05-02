package io.mosip.openID4VP.authorizationResponse

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.dto.vpResponseMetadata.types.LdpVPResponseMetadata
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions.NetworkRequestFailed
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions.NetworkRequestTimeout
import io.mosip.openID4VP.testData.*
import okhttp3.Headers
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import io.mosip.openID4VP.constants.FormatType

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