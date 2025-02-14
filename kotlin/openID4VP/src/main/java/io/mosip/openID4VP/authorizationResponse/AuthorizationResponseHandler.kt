package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.ClientIdScheme
import io.mosip.openID4VP.authorizationRequest.constants.ResponseMode
import io.mosip.openID4VP.authorizationRequest.constants.ResponseType
import io.mosip.openID4VP.authorizationResponse.models.AuthorizationResponse
import io.mosip.openID4VP.authorizationResponse.models.vpToken.CredentialFormatSpecificVPToken
import io.mosip.openID4VP.authorizationResponse.models.vpToken.types.LdpVPToken
import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.CredentialFormatSpecificSigningData
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenFactory
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.common.FormatType
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.dto.VPResponseMetadata.VPResponseMetadata
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest

private val className = AuthorizationResponseHandler::class.java.simpleName

class AuthorizationResponseHandler {
    private lateinit var vpToken: VPTokenType
    private var vpTokensForSigning: Map<FormatType, CredentialFormatSpecificSigningData> =
        mutableMapOf()
    private lateinit var authorizationRequest: AuthorizationRequest
    private var path: MutableMap<FormatType, Pair<Int, Int>> = mutableMapOf()

    @Throws(Exception::class)
    fun constructDataForSigning(credentialsMap: Map<String, Map<String, List<Any>>>): Map<FormatType, CredentialFormatSpecificSigningData> {
        vpTokensForSigning =
            CredentialFormatSpecificSigningDataMapCreator().create(selectedCredentials = credentialsMap)
        return vpTokensForSigning
    }

    fun createAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        signingDataForAuthorizationResponseCreation: Map<FormatType, VPResponseMetadata>,
        vpTokensForSigning: Map<FormatType, CredentialFormatSpecificSigningData>,
        credentialsMap: Map<String, Map<String, List<Any>>>,
    ): AuthorizationResponse {
        this.authorizationRequest = authorizationRequest
        this.vpTokensForSigning = vpTokensForSigning

        when (authorizationRequest.responseType) {
            ResponseType.vp_token.value -> {
                val vpToken = createVPToken(signingDataForAuthorizationResponseCreation)
                val presentationSubmission = createPresentationSubmission(
                    credentialsMap = credentialsMap,
                    authorizationRequest = authorizationRequest
                )

                return AuthorizationResponse(
                    vpToken = vpToken,
                    presentationSubmission = presentationSubmission
                )
            }

            else -> throw Logger.handleException(
                exceptionType = "UnsupportedResponseType",
                className = className,
                message = "Provided response_type ${authorizationRequest.responseType} is not supported by the library"
            )
        }
    }

    fun sendAuthorizationResponseToVerifier(
        authorizationResponse: AuthorizationResponse,
        authorizationRequest: AuthorizationRequest,
    ): String {
        when (authorizationRequest.responseMode) {
            ResponseMode.directPost.value -> {
                // 1.Gather request body items
                val bodyParams = mutableMapOf(
                    "state" to authorizationRequest.state
                )
                // 1.1 Add authorization response in encoded form
                bodyParams.putAll(authorizationResponse.encodedItems())

                // 2. make api call
                try {
                    val responseUri: String = authorizationRequest.responseUri
                        ?: if (authorizationRequest.clientIdScheme == ClientIdScheme.REDIRECT_URI.value) {
                            authorizationRequest.redirectUri!!
                        } else {
                            return ""
                        }
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

            else -> {
                // In case of response_mode not available in authorization request, default mode is fragment
                throw Logger.handleException(
                    exceptionType = "UnsupportedResponseMode",
                    className = className,
                    message = "Provided response_mode ${authorizationRequest.responseMode} is not supported by the library"
                )
            }
        }


    }

    @Throws(Exception::class)
    private fun createVPToken(vpTokenForSigning: Map<FormatType, VPResponseMetadata>): VPTokenType {
        val vpTokenOfCredentials = mutableListOf<CredentialFormatSpecificVPToken>()

        var count = 0
        for ((credentialFormat, vpResponseMetadata) in vpTokenForSigning) {
            try {
                val vpTokenBuilder = VPTokenFactory(
                    vpResponseMetadata = vpResponseMetadata,
                    vpTokenForSigning = vpTokensForSigning[credentialFormat]!!,
                    nonce = authorizationRequest.nonce
                ).getVPTokenBuilder(credentialFormat)

                val credentialSpecificVPToken = vpTokenBuilder.build()
                vpTokenOfCredentials.add(credentialSpecificVPToken)
                path[credentialFormat] = Pair(count, count)
                count++
            } catch (error: Exception) {
                throw error
            }
        }
        vpToken = if (vpTokenOfCredentials.size == 1) {
            VPTokenType.VPToken(
                value = vpTokenOfCredentials[0]
            )
        } else {
            VPTokenType.VPTokenArray(vpTokenOfCredentials)
        }

        return vpToken
    }

    @Throws(Exception::class)
    private fun createPresentationSubmission(
        credentialsMap: Map<String, Map<String, List<Any>>>,
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

    @Throws(Exception::class)
    private fun createInputDescriptor(credentialsMap: Map<String, Map<String, List<Any>>>): List<DescriptorMap> {
        //TODO: Handle for single VP
        //In case of only single VP, presentation_submission -> path = $, path_nest = $.<credentialPathIdentifier - internalPath>[n]
        //and in case of multiple VPs, presentation_submission -> path = $[i], path_nest = $[i].<credentialPathIdentifier - internalPath>[n]
        val descriptorsMap: MutableList<DescriptorMap> = mutableListOf()
        val formatTypeMap: Map<String, FormatType> = mapOf("ldp_vc" to FormatType.ldp_vc)
        val isSingleVPSharing: Boolean = path.keys.size == 1

        for ((inputDescriptorId, matchingVcs) in credentialsMap) {
            try {
                for ((format, _) in matchingVcs) {
                    var formatType: FormatType? = formatTypeMap[format]
                    val pathIndex = path[formatType]?.first ?: path.size
                    var nestedPathIndex = path[formatType]?.second ?: 0
                    val pathIndexValue = if (isSingleVPSharing) "$" else "$[$pathIndex]"
                    if (format == FormatType.ldp_vc.name) {
                        formatType = FormatType.ldp_vc
                        descriptorsMap.add(
                            DescriptorMap(
                                id = inputDescriptorId,
                                format = FormatType.ldp_vc.value,
                                path = pathIndexValue,
                                pathNested = "$pathIndexValue.${LdpVPToken.internalPath}[$nestedPathIndex]"
                            )
                        )
                    }
                    requireNotNull(formatType) {
                        throw Logger.handleException(
                            exceptionType = "UnsupportedFormatOfLibrary",
                            className = className
                        )
                    }
                    nestedPathIndex += 1
                    path[formatType] = Pair(pathIndex, nestedPathIndex + 1)
                }
            } catch (e: Exception) {
                throw e
            }
        }

        return descriptorsMap
    }


}