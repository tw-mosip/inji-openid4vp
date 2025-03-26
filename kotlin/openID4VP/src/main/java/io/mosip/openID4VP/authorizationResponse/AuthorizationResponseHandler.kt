package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.constants.ResponseType
import io.mosip.openID4VP.authorizationResponse.models.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.models.unsignedVPToken.types.UnsignedLdpVPToken
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PathNested
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenFactory
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType.VPTokenArray
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType.VPTokenElement
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldpVp.LdpVPToken
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.constants.VPFormatType
import io.mosip.openID4VP.dto.vpResponseMetadata.VPResponseMetadata
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory

private val className = AuthorizationResponseHandler::class.java.simpleName

internal class AuthorizationResponseHandler {
    private lateinit var credentialsMap: Map<String, Map<FormatType, List<Any>>>
    private lateinit var unsignedVPTokens: Map<FormatType, UnsignedVPToken>

    fun constructUnsignedVPToken(
        credentialsMap: Map<String, Map<FormatType, List<Any>>>,
    ): Map<FormatType, UnsignedVPToken> {
        if (credentialsMap.isEmpty()) {
            throw Logger.handleException(
                exceptionType = "InvalidData",
                className = className,
                message = "Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request."
            )
        }
        this.credentialsMap = credentialsMap
        this.unsignedVPTokens = createUnsignedVPTokens()
        return this.unsignedVPTokens
    }

    fun shareVP(
        authorizationRequest: AuthorizationRequest,
        vpResponsesMetadata: Map<FormatType, VPResponseMetadata>,
        responseUri: String,
    ): String {
        val authorizationResponse: AuthorizationResponse = createAuthorizationResponse(
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
    ): AuthorizationResponse {
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
                return AuthorizationResponse(
                    presentationSubmission = presentationSubmission,
                    vpToken = vpToken,
                    state = authorizationRequest.state
                )
            }

            else -> throw Logger.handleException(
                exceptionType = "InvalidData",
                className = className,
                message = "Provided response_type - ${authorizationRequest.responseType} is not supported"
            )
        }
    }

    //Send authorization response to verifier based on the response_mode parameter in authorization request
    private fun sendAuthorizationResponse(
        authorizationResponse: AuthorizationResponse,
        responseUri: String,
        authorizationRequest: AuthorizationRequest,
    ): String {
        return ResponseModeBasedHandlerFactory.get(authorizationRequest.responseMode!!)
            .sendAuthorizationResponse(
                authorizationRequest = authorizationRequest,
                url = responseUri,
                authorizationResponse = authorizationResponse
            )
    }

    private fun createVPToken(
        vpResponsesMetadata: Map<FormatType, VPResponseMetadata>,
        authorizationRequest: AuthorizationRequest,
        credentialFormatIndex: MutableMap<FormatType, Int>,
    ): VPTokenType {
        val vpTokens: MutableList<VPToken> = mutableListOf()

        vpResponsesMetadata.entries.forEachIndexed { index, (credentialFormat, vpResponseMetadata) ->
            vpTokens.add(
                VPTokenFactory(
                    vpResponseMetadata = vpResponseMetadata,
                    unsignedVpToken = unsignedVPTokens[credentialFormat]
                        ?: throw Logger.handleException(
                            exceptionType = "InvalidData",
                            message = "unable to find the related credential format - $credentialFormat in the unsignedVPTokens map",
                            className = className
                        ),
                    nonce = authorizationRequest.nonce
                ).getVPTokenBuilder(credentialFormat).build()
            )
            credentialFormatIndex[credentialFormat] = index
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
        val descriptorMap = createInputDescriptor(credentialFormatIndex)

        return PresentationSubmission(
            id = UUIDGenerator.generateUUID(),
            definitionId = authorizationRequest.presentationDefinition.id,
            descriptorMap = descriptorMap,
        )
    }

    private fun createInputDescriptor(credentialFormatIndex: MutableMap<FormatType, Int>): List<DescriptorMap> {
        //In case of only single VP, presentation_submission -> path = $, path_nest = $.<credentialPathIdentifier - internalPath>[n]
        //and in case of multiple VPs, presentation_submission -> path = $[i], path_nest = $[i].<credentialPathIdentifier - internalPath>[n]
        val isMultipleVpTokens: Boolean = credentialFormatIndex.keys.size > 1
        val formatTypeToCredentialIndex: MutableMap<FormatType, Int> = mutableMapOf()

        val descriptorMappings =
            credentialsMap.toSortedMap().map { (inputDescriptorId, formatMap) ->
                formatMap.flatMap { (credentialFormat, credentials) ->
                    val vpTokenIndex = credentialFormatIndex[credentialFormat]

                    credentials.map {
                        val rootLevelPath = when {
                            isMultipleVpTokens -> "$[$vpTokenIndex]"
                            else -> "$"
                        }
                        val credentialIndex =
                            (formatTypeToCredentialIndex[credentialFormat] ?: -1) + 1
                        val vpFormat: String
                        val pathNested: PathNested?
                        when (credentialFormat) {
                            FormatType.LDP_VC -> {
                                val relativePath = "$.${LdpVPToken.INTERNAL_PATH}[$credentialIndex]"
                                vpFormat = VPFormatType.LDP_VP.value
                                pathNested = PathNested(
                                    id = inputDescriptorId,
                                    format = credentialFormat.value,
                                    path = relativePath
                                )
                            }
                        }
                        formatTypeToCredentialIndex[credentialFormat] = credentialIndex

                        DescriptorMap(
                            id = inputDescriptorId,
                            format = vpFormat,
                            path = rootLevelPath,
                            pathNested = pathNested
                        )
                    }
                }

            }
        return descriptorMappings.flatten()
    }

    private fun createUnsignedVPTokens(): Map<FormatType, UnsignedVPToken> {
        val groupedVcs: Map<FormatType, List<Any>> = credentialsMap.toSortedMap().values
            .flatMap { it.entries }
            .groupBy({ it.key }, { it.value }).mapValues { (_, lists) ->
                lists.flatten()
            }

        // group all formats together, call specific creator and pass the grouped credentials
        return groupedVcs.mapValues { (format, credentialsArray) ->
            when (format) {
                FormatType.LDP_VC -> {
                    val verifiableCredentials: List<String> = credentialsArray.map {
                        it as? String ?: throw Logger.handleException(
                            exceptionType = "InvalidData",
                            className = className,
                            message = "$format credentials are not passed in string format"
                        )
                    }
                    UnsignedLdpVPToken(
                        verifiableCredential = verifiableCredentials,
                        id = UUIDGenerator.generateUUID(),
                        holder = ""
                    )
                }
            }
        }
    }
}