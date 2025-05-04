package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPToken
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PathNested
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenFactory
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType.VPTokenArray
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType.VPTokenElement
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPToken
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.common.getNonce
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.ResponseType
import io.mosip.openID4VP.constants.VPFormatType
import io.mosip.openID4VP.authorizationResponse.authenticationContainer.AuthenticationContainer
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPTokenBuilder
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory

private val className = AuthorizationResponseHandler::class.java.simpleName

internal class AuthorizationResponseHandler {
    private lateinit var credentialsMap: Map<String, Map<FormatType, List<String>>>
    private lateinit var unsignedVPTokens: Map<FormatType, UnsignedVPToken>
    private val walletNonce = getNonce(16)

    fun constructUnsignedVPToken(
        credentialsMap: Map<String, Map<FormatType, List<String>>>,
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
    ): Map<FormatType, UnsignedVPToken> {
        if (credentialsMap.isEmpty()) {
            throw Logger.handleException(
                exceptionType = "InvalidData",
                className = className,
                message = "Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request."
            )
        }
        this.credentialsMap = credentialsMap
        this.unsignedVPTokens = createUnsignedVPTokens(authorizationRequest, responseUri)
        return this.unsignedVPTokens
    }

    fun shareVP(
        authorizationRequest: AuthorizationRequest,
        authenticationContainerMap: Map<FormatType, AuthenticationContainer>,
        responseUri: String,
    ): String {
        val authorizationResponse: AuthorizationResponse = createAuthorizationResponse(
            authorizationRequest = authorizationRequest,
            authenticationContainerMap = authenticationContainerMap
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
        authenticationContainerMap: Map<FormatType, AuthenticationContainer>,
    ): AuthorizationResponse {
        when (authorizationRequest.responseType) {
            ResponseType.VP_TOKEN.value -> {
                val credentialFormatIndex: MutableMap<FormatType, Int> = mutableMapOf()
                val vpToken = createVPToken(
                    authenticationContainerMap,
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
                authorizationResponse = authorizationResponse,
                walletNonce = walletNonce,
            )
    }

    private fun createVPToken(
        authenticationContainerMap: Map<FormatType, AuthenticationContainer>,
        authorizationRequest: AuthorizationRequest,
        credentialFormatIndex: MutableMap<FormatType, Int>,
    ): VPTokenType {
        val vpTokens: MutableList<VPToken> = mutableListOf()

        val groupedVcs: Map<FormatType, List<String>> = credentialsMap.values
            .flatMap { it.entries }
            .groupBy({ it.key }, { it.value }).mapValues { (_, lists) ->
                lists.flatten()
            }

        authenticationContainerMap.entries.forEachIndexed { index, (credentialFormat, authenticationContainer) ->
            vpTokens.add(
                VPTokenFactory(
                    authenticationContainer = authenticationContainer,
                    unsignedVpToken = unsignedVPTokens[credentialFormat]
                        ?: throw Logger.handleException(
                            exceptionType = "InvalidData",
                            message = "unable to find the related credential format - $credentialFormat in the unsignedVPTokens map",
                            className = className
                        ),
                    credentials = groupedVcs[credentialFormat],
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
                        var pathNested: PathNested? = null
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
                            FormatType.MSO_MDOC -> {
                                vpFormat = VPFormatType.MSO_MDOC.value
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

    private fun createUnsignedVPTokens(
        authorizationRequest: AuthorizationRequest,
        responseUri: String
    ): Map<FormatType, UnsignedVPToken> {
        val groupedVcs: Map<FormatType, List<String>> = credentialsMap.toSortedMap().values
            .flatMap { it.entries }
            .groupBy({ it.key }, { it.value }).mapValues { (_, lists) ->
                lists.flatten()
            }

        // group all formats together, call specific creator and pass the grouped credentials
        return groupedVcs.mapValues { (format, credentialsArray) ->
            when (format) {
                FormatType.LDP_VC -> {
                    UnsignedLdpVPTokenBuilder(
                        verifiableCredential = credentialsArray,
                        id = UUIDGenerator.generateUUID(),
                        holder = ""
                    ).build()
                }

                FormatType.MSO_MDOC -> {
                    UnsignedMdocVPTokenBuilder(
                        mdocCredentials = credentialsArray,
                        clientId = authorizationRequest.clientId,
                        responseUri = responseUri,
                        verifierNonce = authorizationRequest.nonce,
                        mdocGeneratedNonce = walletNonce
                    ).build()
                }
            }
        }
    }
}