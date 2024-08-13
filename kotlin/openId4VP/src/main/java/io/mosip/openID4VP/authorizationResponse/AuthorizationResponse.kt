package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.OpenId4VP
import io.mosip.openID4VP.authorizationResponse.exception.AuthorizationResponseExceptions
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.VPToken
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.VPTokenForSigning
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.dto.VPResponseMetadata
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHttpPostRequest
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.IOException

class AuthorizationResponse {
    companion object {
        private val logTag = Logger.getLogTag(this::class.simpleName!!)
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


            return try {
                Json.encodeToString(vpTokenForSigning)
            } catch (exception: SerializationException) {
                throw AuthorizationResponseExceptions.JsonEncodingException(exception.message!!)
            }
        }

        fun shareVP(vpResponseMetadata: VPResponseMetadata, openId4VP: OpenId4VP): String {
            try {
                vpResponseMetadata.validate()
                var pathIndex = 0
                val proof = Proof.constructProof(
                    vpResponseMetadata, challenge = openId4VP.authorizationRequest.nonce
                )
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
                val presentationSubmission = PresentationSubmission(
                    UUIDGenerator.generateUUID(), openId4VP.presentationDefinitionId, descriptorMap
                )
                val vpToken = VPToken.constructVpToken(this.vpTokenForSigning, proof)

                return constructHttpRequestBody(
                    vpToken,
                    presentationSubmission,
                    openId4VP.authorizationRequest.responseUri,
                )
            } catch (exception: Exception) {
                throw exception
            }
        }

        private fun constructHttpRequestBody(
            vpToken: VPToken,
            presentationSubmission: PresentationSubmission,
            responseUri: String,
        ): String {
            try {
                val encodedVPToken = Json.encodeToString(vpToken)
                val encodedPresentationSubmission = Json.encodeToString(presentationSubmission)
                val queryParams = mapOf(
                    "vp_token" to encodedVPToken,
                    "presentation_submission" to encodedPresentationSubmission
                )

                return sendHttpPostRequest(responseUri, queryParams)
            } catch (exception: SerializationException) {
                val e = AuthorizationResponseExceptions.JsonEncodingException(exception.message!!)
                Logger.error(logTag, e)
                throw e
            } catch (exception: Exception) {
                throw exception
            }
        }
    }
}