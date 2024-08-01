package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.OpenId4VP
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.VPToken
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.VPTokenForSigning
import io.mosip.openID4VP.networkManager.NetworkManager.Companion.sendHttpPostRequest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.Response

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

    fun shareVP(jws: String, signatureAlgorithm: String, publicKey: String, domain: String, openId4VP: OpenId4VP): Response{
        var pathIndex = 0
        val proof = Proof.constructProof(signingAlgorithm = signatureAlgorithm, challenge = openId4VP.authorizationRequest.nonce, domain = domain, jws = jws, publicKey = publicKey )
        val descriptorMap = mutableListOf<DescriptorMap>()

        selectedVerifiableCredentials.forEach { (inputDescriptorId, vcs) ->
            vcs.forEach { _ ->
                descriptorMap.add(DescriptorMap(inputDescriptorId,"ldp_vp","$.verifiableCredential[${pathIndex++}]"))
            }
        }

        val presentationSubmission = PresentationSubmission("123", openId4VP.presentationDefinitionId, descriptorMap)
        val vpToken =  VPToken.constructVpToken(this.vpTokenForSigning, proof)

        return constructHttpRequestBody(vpToken, presentationSubmission, openId4VP.authorizationRequest.responseUri)
    }

    private fun constructHttpRequestBody(vpToken: VPToken, presentationSubmission: PresentationSubmission, responseUri: String): Response{
        val encodedVPToken = Json.encodeToString(vpToken)
        val encodedPresentationSubmission = Json.encodeToString(presentationSubmission)

        val requestBody = """
        {
        "vp_token": $encodedVPToken,
        "presentation_submission": $encodedPresentationSubmission
        }
        """.trimIndent()

        return sendHttpPostRequest(requestBody, responseUri)
    }
}