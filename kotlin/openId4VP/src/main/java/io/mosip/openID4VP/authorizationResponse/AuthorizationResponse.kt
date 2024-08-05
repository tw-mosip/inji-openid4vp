package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.OpenId4VP
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.VPToken
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.VPTokenForSigning
import io.mosip.openID4VP.dto.VPResponseMetadata
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHttpPostRequest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.Response
import java.io.IOException

class AuthorizationResponse {

    private lateinit var vpTokenForSigning: VPTokenForSigning
    private lateinit var selectedVerifiableCredentials: Map<String, List<String>>
    fun constructVPTokenForSigning(selectedVerifiableCredentials: Map<String,List<String>>): String {
        this.selectedVerifiableCredentials = selectedVerifiableCredentials
        val verifiableCredential = mutableListOf<String>()
        selectedVerifiableCredentials.forEach { (_,vcs) ->
            vcs.forEach { vcJson ->
                verifiableCredential.add(vcJson)
            }
        }
        this.vpTokenForSigning = VPTokenForSigning(verifiableCredential = verifiableCredential, id="", holder ="")

        return Json.encodeToString(this.vpTokenForSigning)
    }

    fun shareVP(vpResponseMetadata: VPResponseMetadata, openId4VP: OpenId4VP): Response? {
        try {
            vpResponseMetadata.validate()
            var pathIndex = 0
            val proof = Proof.constructProof( vpResponseMetadata, challenge = openId4VP.authorizationRequest.nonce)
            val descriptorMap = mutableListOf<DescriptorMap>()

            selectedVerifiableCredentials.forEach { (inputDescriptorId, vcs) ->
                vcs.forEach { _ ->
                    descriptorMap.add(DescriptorMap(inputDescriptorId,"ldp_vp","$.verifiableCredential[${pathIndex++}]"))
                }
            }

            val presentationSubmission = PresentationSubmission("123", openId4VP.presentationDefinitionId, descriptorMap)
            val vpToken =  VPToken.constructVpToken(this.vpTokenForSigning, proof)

            return constructHttpRequestBody(vpToken, presentationSubmission, openId4VP.authorizationRequest.responseUri, vpResponseMetadata.sharingTimeoutInMilliseconds)
        }catch (exception: IOException){
            throw exception
        }
    }

    private fun constructHttpRequestBody(vpToken: VPToken, presentationSubmission: PresentationSubmission, responseUri: String, sharingTimeoutInMilliseconds: Number): Response? {
        try {
            val encodedVPToken = Json.encodeToString(vpToken)
            val encodedPresentationSubmission = Json.encodeToString(presentationSubmission)

            val queryParams = mapOf("vp_token" to encodedVPToken, "presentation_submission" to encodedPresentationSubmission)

            return sendHttpPostRequest(responseUri, queryParams, sharingTimeoutInMilliseconds)
        }catch (exception: IOException){
            throw exception
        }
    }
}