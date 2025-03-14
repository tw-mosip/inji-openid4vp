package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.constants.ResponseType
import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.VPTokenForSigning
import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.types.LdpVPTokenForSigning
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PathNested
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenFactory
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType.VPTokenArray
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType.VPTokenElement
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldpVp.LdpVPToken
import io.mosip.openID4VP.common.FormatType
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.dto.VPResponseMetadata.VPResponseMetadata
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory
import okhttp3.internal.toImmutableMap

private val className = AuthorizationResponseHandler::class.java.simpleName

class AuthorizationResponseHandler {
    private lateinit var credentialsMap: Map<String, Map<FormatType, List<String>>>
    private lateinit var vpTokensForSigning: Map<FormatType, VPTokenForSigning>

    fun constructVPTokenForSigning(
        credentialsMap: Map<String, Map<FormatType, List<String>>>,
        holder: String
    ): Map<FormatType, VPTokenForSigning> {
        this.credentialsMap = credentialsMap
        if (credentialsMap.isEmpty()) {
            throw Logger.handleException(
                exceptionType = "EmptyCredentialsList",
                className = className,
                message = "Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request."
            )
        }
        this.vpTokensForSigning = createVPTokenForSigning(credentialsMap, holder)
        return this.vpTokensForSigning
    }

    fun shareVP(
        authorizationRequest: AuthorizationRequest,
        vpResponsesMetadata: Map<FormatType, VPResponseMetadata>,
        responseUri: String,
    ): String {
        val authorizationResponse: Map<String, Any> = createAuthorizationResponse(
            authorizationRequest = authorizationRequest,
            vpResponsesMetadata = vpResponsesMetadata
        )

        return sendAuthorizationResponse(
            authorizationResponse = authorizationResponse,
            responseUri = responseUri,
            authorizationRequest = authorizationRequest
        )
    }

    //Create authorization response based on the response_type parameter in authorization response
    private fun createAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        vpResponsesMetadata: Map<FormatType, VPResponseMetadata>,
    ): Map<String, Any> {
        when (authorizationRequest.responseType) {
            ResponseType.VP_TOKEN.value -> {
                val credentialFormatIndex: MutableMap<FormatType, Int> = mutableMapOf()
                val vpToken = createVPToken(
                    vpResponsesMetadata,
                    authorizationRequest,
                    credentialFormatIndex
                )
                val presentationSubmission: PresentationSubmission = createPresentationSubmission(
                    authorizationRequest = authorizationRequest,
                    credentialFormatIndex = credentialFormatIndex
                )
                return buildMap {
                    put("vp_token", vpToken)
                    put(
                        "presentation_submission",
                        presentationSubmission
                    )
                    authorizationRequest.state?.let { put("state", it) }
                }.toImmutableMap()
            }

            else -> throw Logger.handleException(
                exceptionType = "UnsupportedResponseType",
                className = className,
                message = "Provided response_type - ${authorizationRequest.responseType} is not supported"
            )
        }
    }

    //Send authorization response to verifier based on the response_mode parameter in authorization request
    private fun sendAuthorizationResponse(
        authorizationResponse: Map<String, Any>,
        responseUri: String,
        authorizationRequest: AuthorizationRequest,
    ): String {
        return ResponseModeBasedHandlerFactory.get(authorizationRequest.responseMode!!)
            .sendAuthorizationResponse(
                vpToken = authorizationResponse["vp_token"] as VPTokenType,
                authorizationRequest = authorizationRequest,
                presentationSubmission = authorizationResponse["presentation_submission"] as PresentationSubmission,
                state = authorizationRequest.state,
                url = responseUri
            )
    }

    private fun createVPToken(
        vpResponsesMetadata: Map<FormatType, VPResponseMetadata>,
        authorizationRequest: AuthorizationRequest,
        credentialFormatIndex: MutableMap<FormatType, Int>,
    ): VPTokenType {
        val vpTokens: MutableList<VPToken> = mutableListOf()

        var count = 0
        for ((credentialFormat, vpResponseMetadata) in vpResponsesMetadata) {
            val vpToken = VPTokenFactory(
                vpResponseMetadata = vpResponseMetadata,
                vpTokenForSigning = vpTokensForSigning[credentialFormat] ?: throw Logger.handleException(
                    exceptionType = "InvalidData",
                    className = className
                ),
                nonce = authorizationRequest.nonce
            ).getVPTokenBuilder(credentialFormat).build()

            vpTokens.add(vpToken)
            credentialFormatIndex[credentialFormat] = count
            count++
        }

        val vpToken: VPTokenType = vpTokens.takeIf { it.size == 1 }
            ?.let { VPTokenElement(it[0]) }
            ?: VPTokenArray(vpTokens)

        return vpToken
    }

    private fun createPresentationSubmission(
        authorizationRequest: AuthorizationRequest,
        credentialFormatIndex: MutableMap<FormatType, Int>,
    ): PresentationSubmission {
        val descriptorMap = createInputDescriptor(credentialsMap, credentialFormatIndex)
        val presentationDefinitionId = authorizationRequest.presentationDefinition.id

        return PresentationSubmission(
            id = UUIDGenerator.generateUUID(),
            definitionId = presentationDefinitionId,
            descriptorMap = descriptorMap,
        )
    }

    private fun createInputDescriptor(
        credentialsMap: Map<String, Map<FormatType, List<String>>>,
        credentialFormatIndex: MutableMap<FormatType, Int>,
    ): List<DescriptorMap> {
        //In case of only single VP, presentation_submission -> path = $, path_nest = $.<credentialPathIdentifier - internalPath>[n]
        //and in case of multiple VPs, presentation_submission -> path = $[i], path_nest = $[i].<credentialPathIdentifier - internalPath>[n]
        val multipleVpTokens: Boolean = credentialFormatIndex.keys.size > 1
        val formatTypeToCredentialIndex: MutableMap<FormatType, Int> = mutableMapOf()

        val descriptorMappings =
            credentialsMap.toSortedMap().map { (inputDescriptorId, formatMap) ->
                formatMap.flatMap { (format, credentials) ->
                    val vpTokenIndex = credentialFormatIndex[format]

                    credentials.map {
                        val rootLevelPath = when {
                            multipleVpTokens -> "$[$vpTokenIndex]"
                            else -> "$"
                        }
                        val credentialIndex = (formatTypeToCredentialIndex[format] ?: -1) + 1
                        val relativePath = when (format) {
                            FormatType.LDP_VC -> "$.${LdpVPToken.INTERNAL_PATH}[$credentialIndex]"
                        }
                        formatTypeToCredentialIndex[format] = credentialIndex

                        DescriptorMap(
                            id = inputDescriptorId,
                            format = format.value,
                            path = rootLevelPath,
                            pathNested = PathNested(
                                id = inputDescriptorId,
                                format = format.value,
                                path = relativePath
                            )
                        )
                    }
                }

            }
        return descriptorMappings.flatten()
    }

    private fun createVPTokenForSigning(
        credentialsMap: Map<String, Map<FormatType, List<String>>>,
        holder: String
    ): Map<FormatType, VPTokenForSigning> {
        val groupedVcs: Map<FormatType, List<String>> = credentialsMap.toSortedMap().values
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
                    holder = holder
                )
            }
        }
    }
}