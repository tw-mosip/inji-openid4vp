package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.VPToken
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.VPTokenForSigning
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.common.encode
import io.mosip.openID4VP.dto.VPResponseMetadata
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory

private val className = AuthorizationResponse::class.simpleName!!

class AuthorizationResponse {
    companion object {
        private lateinit var vpTokenForSigning: VPTokenForSigning
        private lateinit var verifiableCredentials: Map<String, List<String>>

        fun constructVPTokenForSigning(verifiableCredentials: Map<String, List<String>>): String {
            this.verifiableCredentials = verifiableCredentials
            val verifiableCredential = mutableListOf<String>()
            verifiableCredentials.forEach { (_, vcs) ->
                vcs.forEach { vcJson ->
                    verifiableCredential.add(vcJson)
                }
            }
            this.vpTokenForSigning = VPTokenForSigning(
                verifiableCredential = verifiableCredential,
                id = UUIDGenerator.generateUUID(),
                holder = ""
            )
            return encode(vpTokenForSigning, "vp_token_for_signing", className)
        }

        fun shareVP(
            vpResponseMetadata: VPResponseMetadata,
            authorizationRequest: AuthorizationRequest,
            responseUri: String,
        ): String {
            vpResponseMetadata.validate()

            val presentationSubmission = PresentationSubmission(
                id = UUIDGenerator.generateUUID(),
                definitionId = authorizationRequest.clientId,
                descriptorMap = createDescriptorMap(this.verifiableCredentials)
            )
            val vpToken = VPToken.construct(
                signingVPToken = this.vpTokenForSigning,
                proof = Proof.construct(
                    vpResponseMetadata = vpResponseMetadata,
                    challenge = authorizationRequest.nonce
                )
            )
            return ResponseModeBasedHandlerFactory.get(authorizationRequest.responseMode!!)
                .sendAuthorizationResponse(
                    vpToken = vpToken,
                    authorizationRequest = authorizationRequest,
                    presentationSubmission = presentationSubmission,
                    state = authorizationRequest.state,
                    url = responseUri
                )

        }

        private fun createDescriptorMap(verifiableCredentials: Map<String, List<String>>): MutableList<DescriptorMap> {
            var pathIndex = 0
            val descriptorMap = mutableListOf<DescriptorMap>()
            verifiableCredentials.forEach { (inputDescriptorId, vcs) ->
                vcs.forEach { _ ->
                    descriptorMap.add(
                        DescriptorMap(
                            inputDescriptorId,
                            "ldp_vp",
                            "$.verifiableCredential[${pathIndex++}]"
                        )
                    )
                }
            }
            return descriptorMap
        }

    }
}