package io.mosip.openID4VP.authorizationResponse

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.constants.ResponseType
import io.mosip.openID4VP.authorizationResponse.models.vpToken.VPToken
import io.mosip.openID4VP.authorizationResponse.models.vpToken.types.LdpVPToken
import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.VPTokenForSigning
import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.types.LdpVPTokenForSigning
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenFactory
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.common.FormatType
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.dto.VPResponseMetadata.VPResponseMetadata
import io.mosip.openID4VP.networkManager.CONTENT_TYPES
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import okhttp3.internal.toImmutableMap

private val className = AuthorizationResponseHandler::class.java.simpleName

class AuthorizationResponseHandler {
    //TODO: check the usage of the value over here
    private var credentialFormatIndex: MutableMap<FormatType, Pair<Int, Int>> = mutableMapOf()

    fun constructVPTokenForSigning(credentialsMap: Map<String, Map<FormatType, List<String>>>): Map<FormatType, VPTokenForSigning> {
        if (credentialsMap.isEmpty()) {
            throw Logger.handleException(
                exceptionType = "EmptyCredentialsList",
                className = className,
                message = "The Wallet did not have the requested Credentials to satisfy the Authorization Request."
            )
        }
        return createVPTokenForSigning(credentialsMap)
    }

    fun shareVP(
        authorizationRequest: AuthorizationRequest,
        vpResponsesMetadata: Map<FormatType, VPResponseMetadata>,
        credentialsMap: Map<String, Map<FormatType, List<String>>>,
        vpTokensForSigning: Map<FormatType, VPTokenForSigning>,
        responseUri: String,
    ): String {
        val authorizationResponse: Map<String, String> = createAuthorizationResponse(
            authorizationRequest = authorizationRequest,
            vpResponsesMetadata = vpResponsesMetadata,
            credentialsMap = credentialsMap,
            vpTokensForSigning = vpTokensForSigning
        )

        return sendAuthorizationResponse(
            authorizationResponse = authorizationResponse,
            responseUri = responseUri
        )
    }

    //Create authorization response based on the response_type parameter in authorization request
    private fun createAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        vpResponsesMetadata: Map<FormatType, VPResponseMetadata>,
        credentialsMap: Map<String, Map<FormatType, List<String>>>,
        vpTokensForSigning: Map<FormatType, VPTokenForSigning>,
    ): Map<String, String> {
        when (authorizationRequest.responseType) {
            ResponseType.VP_TOKEN.value -> {
                val vpToken = createVPToken(
                    vpResponsesMetadata,
                    authorizationRequest,
                    vpTokensForSigning
                )
                val presentationSubmission: PresentationSubmission = createPresentationSubmission(
                    credentialsMap = credentialsMap,
                    authorizationRequest = authorizationRequest
                )
                return buildMap {
                    put("vp_token",jacksonObjectMapper().writeValueAsString(vpToken))
                    put("presentation_submission",jacksonObjectMapper().writeValueAsString(presentationSubmission))
                    authorizationRequest.state?.let { put("state", it) }
                }.toImmutableMap()
            }
            else -> throw Logger.handleException(
                exceptionType = "UnsupportedResponseType",
                className = className,
                message = "Provided response_type ${authorizationRequest.responseType} is not supported"
            )
        }
    }

    //Send authorization response to verifier based on the response_mode parameter in authorization request
    private fun sendAuthorizationResponse(
        authorizationResponse: Map<String, String>,
        responseUri: String,
    ): String {
        val response = sendHTTPRequest(
            url = responseUri,
            method = HTTP_METHOD.POST,
            bodyParams = authorizationResponse,
            headers = mapOf("Content-Type" to CONTENT_TYPES.APPLICATION_FORM_URL_ENCODED.value)
        )
        return response["body"].toString()
    }

    private fun createVPToken(
        vpResponsesMetadata: Map<FormatType, VPResponseMetadata>,
        authorizationRequest: AuthorizationRequest,
        vpTokensForSigning: Map<FormatType, VPTokenForSigning>,
    ): VPTokenType {
        val vpTokens: MutableList<VPToken> = mutableListOf()

        var count = 0
        for ((credentialFormat, vpResponseMetadata) in vpResponsesMetadata) {
            val vpToken = VPTokenFactory(
                vpResponseMetadata = vpResponseMetadata,
                vpTokenForSigning = vpTokensForSigning[credentialFormat]!!,
                nonce = authorizationRequest.nonce
            ).getVPTokenBuilder(credentialFormat).build()

            vpTokens.add(vpToken)
            credentialFormatIndex[credentialFormat] = Pair(count, 0)
            count++

        }

        val vpToken: VPTokenType = vpTokens.takeIf { it.size == 1 }
            ?.let { VPTokenType.VPToken(it[0]) }
            ?: VPTokenType.VPTokenArray(vpTokens)

        return vpToken
    }

    private fun createPresentationSubmission(
        credentialsMap: Map<String, Map<FormatType, List<String>>>,
        authorizationRequest: AuthorizationRequest,
    ): PresentationSubmission {
        val descriptorMap = createInputDescriptor(credentialsMap)
        val presentationDefinitionId = authorizationRequest.clientId

        return PresentationSubmission(
            id = UUIDGenerator.generateUUID(),
            definitionId = presentationDefinitionId,
            descriptorMap = descriptorMap
        )
    }

    private fun createInputDescriptor(credentialsMap: Map<String, Map<FormatType, List<String>>>): List<DescriptorMap> {
        //In case of only single VP, presentation_submission -> path = $, path_nest = $.<credentialPathIdentifier - internalPath>[n]
        //and in case of multiple VPs, presentation_submission -> path = $[i], path_nest = $[i].<credentialPathIdentifier - internalPath>[n]
        val descriptorsMap: MutableList<DescriptorMap> = mutableListOf()
        val isSingleVPSharing: Boolean = credentialFormatIndex.keys.size == 1

        for ((inputDescriptorId, matchingVcs) in credentialsMap) {
            try {
                for ((format, _) in matchingVcs) {
                    val pathIndex = credentialFormatIndex[format]?.first ?: credentialFormatIndex.size
                    var nestedPathIndex = credentialFormatIndex[format]?.second ?: 0
                    val pathIndexValue = if (isSingleVPSharing) "$" else "$[$pathIndex]"
                    if (format == FormatType.LDP_VC) {
                        descriptorsMap.add(
                            DescriptorMap(
                                id = inputDescriptorId,
                                format = FormatType.LDP_VC.value,
                                path = pathIndexValue,
                                pathNested = "$pathIndexValue.${LdpVPToken.INTERNAL_PATH}[$nestedPathIndex]"
                            )
                        )
                    }
                    nestedPathIndex += 1
                    credentialFormatIndex[format] = Pair(pathIndex, nestedPathIndex + 1)
                }
            } catch (e: Exception) {
                throw e
            }
        }

        return descriptorsMap
    }

    private fun createVPTokenForSigning(credentialsMap: Map<String, Map<FormatType, List<String>>>): Map<FormatType, VPTokenForSigning> {
        val groupedVcs: Map<FormatType, List<String>> = credentialsMap.values
            .flatMap { it.entries }
            .groupBy({ it.key }, { it.value }).mapValues { (_, lists) ->
                lists.flatten()
            }

        // group all formats together, call specific creator and pass the grouped credentials
        return groupedVcs.mapValues { (format, credentialsArray) ->
            when (format) {
                FormatType.LDP_VC -> LdpVPTokenForSigning(
                    verifiableCredential = credentialsArray,
                    id = UUIDGenerator.generateUUID(),
                    holder = ""
                )
            }
        }
    }
}