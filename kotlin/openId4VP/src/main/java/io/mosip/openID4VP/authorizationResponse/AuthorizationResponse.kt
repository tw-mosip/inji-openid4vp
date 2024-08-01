package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.VPTokenForSigning
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class AuthorizationResponse {
    companion object{
        fun constructVPToken(selectedVerifiableCredentials: Map<String,List<String>>): String {

            var pathIndex = 0
            val descriptorMap = mutableListOf<DescriptorMap>()
            val verifiableCredential = mutableListOf<String>()

            selectedVerifiableCredentials.forEach { (inputDescriptorId, vcs) ->
                vcs.forEach { vcJson ->
                    verifiableCredential.add(vcJson)
                    descriptorMap.add(DescriptorMap(inputDescriptorId,"ldp_vp","$.verifiableCredential[${pathIndex++}]"))
                }
            }

            return Json.encodeToString(VPTokenForSigning(verifiableCredential = verifiableCredential, id="", holder =""))
        }
    }
}