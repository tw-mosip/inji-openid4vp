package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.VPToken
import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.types.LdpVpSpecificSigningData
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.dto.VPResponseMetadata
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

private val logTag = Logger.getLogTag(AuthorizationResponse::class.simpleName!!)
private val className = AuthorizationResponse::class.simpleName!!

class AuthorizationResponse {
    companion object {
        private lateinit var ldpVpSpecificSigningData: LdpVpSpecificSigningData
        private lateinit var verifiableCredentials: Map<String, List<String>>

        fun shareVP(
            vpResponseMetadata: VPResponseMetadata,
            nonce: String,
            state: String,
            responseUri: String,
            presentationDefinitionId: String
        ): String {
            try {
                vpResponseMetadata.validate()
                var pathIndex = 0
                val proof = Proof.constructProof(
                    vpResponseMetadata, challenge = nonce
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
                    UUIDGenerator.generateUUID(), presentationDefinitionId, descriptorMap
                )
                val vpToken = VPToken.constructVpToken(this.ldpVpSpecificSigningData, proof)

                return constructHttpRequestBody(
                    vpToken,
                    presentationSubmission,
                    responseUri, state
                )
            } catch (exception: Exception) {
                Logger.error(logTag, exception)
                throw exception
            }
        }

        private fun constructHttpRequestBody(
            vpToken: VPToken,
            presentationSubmission: PresentationSubmission,
            responseUri: String, state: String
        ): String {
            val encodedVPToken: String
            val encodedPresentationSubmission: String
            try {
                encodedVPToken = Json.encodeToString(vpToken)
            } catch (exception: Exception) {
                throw Logger.handleException(
                    exceptionType = "JsonEncodingFailed",
                    message = exception.message,
                    fieldPath = listOf("vp_token"),
                    className = className
                )
            }
            try {
                encodedPresentationSubmission = Json.encodeToString(presentationSubmission)
            } catch (exception: Exception) {
                throw Logger.handleException(
                    exceptionType = "JsonEncodingFailed",
                    message = exception.message,
                    fieldPath = listOf("presentation_submission"),
                    className = className
                )
            }

            try {
                val bodyParams = mapOf(
                    "vp_token" to encodedVPToken,
                    "presentation_submission" to encodedPresentationSubmission,
                    "state" to state
                )

                return sendHTTPRequest(
                    url = responseUri,
                    method = HTTP_METHOD.POST,
                    bodyParams = bodyParams,
                    headers = mapOf("Content-Type" to "application/x-www-form-urlencoded")
                )
            } catch (exception: Exception) {
                throw exception
            }
        }
    }
}