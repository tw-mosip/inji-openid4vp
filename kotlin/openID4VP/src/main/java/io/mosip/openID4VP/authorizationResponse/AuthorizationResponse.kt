package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.VPToken
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.VPTokenForSigning
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.dto.VPResponseMetadata
import io.mosip.openID4VP.networkManager.CONTENT_TYPE.APPLICATION_FORM_URL_ENCODED
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest


private val logTag = Logger.getLogTag(AuthorizationResponse::class.simpleName!!)

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
            return encode(vpTokenForSigning, "vp_token_for_signing")

        }

        //TODO: discuss that response uri should be passed instead of using the auth request response uri
        fun shareVP(
            vpResponseMetadata: VPResponseMetadata,
            authorizationRequest: AuthorizationRequest,
            responseUri: String,
        ): String {
            try {
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
                val authorizationResponseBody = createAuthorizationResponseBody(
                    vpToken = vpToken,
                    authorizationRequest = authorizationRequest,
                    presentationSubmission = presentationSubmission,
                    state = authorizationRequest.state
                )

                val response = sendHTTPRequest(
                    url = responseUri,
                    method = HTTP_METHOD.POST,
                    bodyParams = authorizationResponseBody,
                    headers = mapOf("Content-Type" to APPLICATION_FORM_URL_ENCODED.value)
                )
                return response["body"].toString()


            } catch (exception: Exception) {
                Logger.error(logTag, exception)
                throw exception
            }
        }
    }
}