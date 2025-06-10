package io.mosip.openID4VP.authorizationResponse

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
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
import io.mosip.openID4VP.common.generateNonce
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.ResponseType
import io.mosip.openID4VP.constants.VPFormatType
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.VPResponseMetadata
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory

private val className = AuthorizationResponseHandler::class.java.simpleName

internal class AuthorizationResponseHandler {
    private lateinit var credentialsMap: Map<String, Map<FormatType, List<Any>>>
    private lateinit var unsignedVPTokens: Map<FormatType, Map<String, Any>>
    private val walletNonce = generateNonce(16)

    fun constructUnsignedVPToken(
        credentialsMap: Map<String, Map<FormatType, List<Any>>>,
        holderId: String,
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
        signatureSuite: String
    ): Map<FormatType, UnsignedVPToken> {
        if (credentialsMap.isEmpty()) {
            throw Logger.handleException(
                exceptionType = "InvalidData",
                className = className,
                message = "Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request."
            )
        }
        this.credentialsMap = credentialsMap
        this.unsignedVPTokens = createUnsignedVPTokens(authorizationRequest, responseUri, holderId, signatureSuite)

        return unsignedVPTokens.mapValues { it.value["unsignedVPToken"] as UnsignedVPToken }
    }

    fun shareVP(
        authorizationRequest: AuthorizationRequest,
        vpTokenSigningResults: Map<FormatType, VPTokenSigningResult>,
        responseUri: String,
    ): String {
        val authorizationResponse: AuthorizationResponse = createAuthorizationResponse(
            authorizationRequest = authorizationRequest,
            vpTokenSigningResults = vpTokenSigningResults
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
        vpTokenSigningResults: Map<FormatType, VPTokenSigningResult>,
    ): AuthorizationResponse {
        when (authorizationRequest.responseType) {
            ResponseType.VP_TOKEN.value -> {
                val credentialFormatIndex: MutableMap<FormatType, Int> = mutableMapOf()
                val vpToken = createVPToken(
                    vpTokenSigningResults,
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
        vpTokenSigningResults: Map<FormatType, VPTokenSigningResult>,
        authorizationRequest: AuthorizationRequest,
        credentialFormatIndex: MutableMap<FormatType, Int>,
    ): VPTokenType {
        val vpTokens: MutableList<VPToken> = mutableListOf()

        vpTokenSigningResults.entries.forEachIndexed { index, (credentialFormat, vpTokenSigningResult) ->
            vpTokens.add(
                VPTokenFactory(
                    vpTokenSigningResult = vpTokenSigningResult,
                    vpTokenSigningPayload = unsignedVPTokens[credentialFormat]?.get("vpTokenSigningPayload")
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
        val isMultipleVPTokens: Boolean = credentialFormatIndex.keys.size > 1
        val formatTypeToCredentialIndex: MutableMap<FormatType, Int> = mutableMapOf()

        val descriptorMappings =
            credentialsMap.toSortedMap().map { (inputDescriptorId, formatMap) ->
                formatMap.flatMap { (credentialFormat, credentials) ->
                    val vpTokenIndex = credentialFormatIndex[credentialFormat]

                    credentials.map {
                        val rootLevelPath = when {
                            isMultipleVPTokens -> "$[$vpTokenIndex]"
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
        println("AuthorizationResponseHandler Descriptor Mappings: $descriptorMappings")
        println("AuthorizationResponseHandler Descriptor Mappings: ${descriptorMappings.flatten()}")
        return descriptorMappings.flatten()
    }

    private fun createUnsignedVPTokens(
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
        holderId: String,
        signatureSuite: String
    ): Map<FormatType, Map<String, Any>> {
        val groupedVcs: Map<FormatType, List<Any>> = credentialsMap.toSortedMap().values
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
                        holder = holderId,
                        challenge = authorizationRequest.nonce,
                        domain = authorizationRequest.clientId,
                        signatureSuite = signatureSuite
                    ).build()
                }

                FormatType.MSO_MDOC -> {
                    UnsignedMdocVPTokenBuilder(
                        mdocCredentials = credentialsArray as List<String>,
                        clientId = authorizationRequest.clientId,
                        responseUri = responseUri,
                        verifierNonce = authorizationRequest.nonce,
                        mdocGeneratedNonce = walletNonce
                    ).build()
                }
            }
        }
    }

    @Deprecated("Use constructUnsignedVPToken instead")
    fun shareVP(
        vpResponseMetadata: VPResponseMetadata,
        nonce: String,
        state: String?,
        responseUri: String,
        presentationDefinitionId: String
    ): String {
        try {
            vpResponseMetadata.validate()
            var pathIndex = 0

            val flattenedCredentials = credentialsMap.mapValues { (_, formatMap) ->
                formatMap.values.first()
            }

            val descriptorMap = mutableListOf<DescriptorMap>()
            flattenedCredentials.forEach { (inputDescriptorId, vcs) ->
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
            val unsignedLdpVPToken =
                unsignedVPTokens[FormatType.LDP_VC]?.get("unsignedLdpVPToken") as LdpVPToken
            val vpToken = unsignedLdpVPToken.apply {
                proof.verificationMethod = vpResponseMetadata.publicKey
                proof.proofValue = vpResponseMetadata.jws
            }

            println("$className VP Token: $vpToken")

            return constructHttpRequestBody(
                vpToken,
                presentationSubmission,
                responseUri, state
            )
        } catch (exception: Exception) {
            throw exception
        }
    }

    @Deprecated("Use constructUnsignedVPToken instead")
    private fun constructHttpRequestBody(
        vpToken: VPToken,
        presentationSubmission: PresentationSubmission,
        responseUri: String, state: String?
    ): String {
        val encodedVPToken: String
        val encodedPresentationSubmission: String
        try {
            encodedVPToken = jacksonObjectMapper().writeValueAsString(vpToken)
        } catch (exception: Exception) {
            throw Logger.handleException(
                exceptionType = "JsonEncodingFailed",
                message = exception.message,
                fieldPath = listOf("vp_token"),
                className = className
            )
        }
        try {
            encodedPresentationSubmission =
                jacksonObjectMapper().writeValueAsString(presentationSubmission)
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
            ).let { baseParams ->
                state?.let { baseParams + mapOf("state" to it) } ?: baseParams
            }

            val response = sendHTTPRequest(
                url = responseUri,
                method = HttpMethod.POST,
                bodyParams = bodyParams,
                headers = mapOf("content-type" to "application/x-www-form-urlencoded")
            )
            return response["body"].toString()
        } catch (exception: Exception) {
            throw exception
        }
    }
}