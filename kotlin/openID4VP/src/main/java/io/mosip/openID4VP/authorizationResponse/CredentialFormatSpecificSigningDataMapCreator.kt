package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.CredentialFormatSpecificSigningData
import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.types.LdpVpSpecificSigningData
import io.mosip.openID4VP.common.FormatType
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.UUIDGenerator

private val className = AuthorizationRequest::class.simpleName!!


class CredentialFormatSpecificSigningDataMapCreator {
    @Throws(Exception::class)
    fun create(selectedCredentials: Map<String, Map<String, List<Any>>>): Map<FormatType, CredentialFormatSpecificSigningData> {
        val signablePayloads: MutableMap<FormatType, CredentialFormatSpecificSigningData> = mutableMapOf()
        val groupedVcs: MutableMap<FormatType, List<Any>> = mutableMapOf()

        // iterate selected credentials
        for ((_, matchingVcs) in selectedCredentials) {
            try {
                for ((format, matchingVcOfFormat: List<Any>) in matchingVcs) {
                    // construct format type
                    var formatType: FormatType? = null
                    if (format == FormatType.ldp_vc.value) {
                        formatType = FormatType.ldp_vc
                    }
                    requireNotNull(formatType) {
                        throw Logger.handleException(
                            exceptionType = "UnsupportedFormatOfLibrary",
                            message = "format $format not supported by library for authorization response",
                            className = className,
                        )
                    }

                    // group all the vp formats together to pass to signable payload creation
                    if (!groupedVcs.containsKey(formatType)) {
                        groupedVcs[formatType] = matchingVcOfFormat
                    } else {
                        val existingData = groupedVcs[formatType]!!.toMutableList()
                        existingData.addAll(matchingVcOfFormat)
                        groupedVcs[formatType] = existingData
                    }
                }
            } catch (error: Exception) {
                throw error
            }
        }

        // group all formats together, call specific creator and pass the grouped credentials
        for ((credentialFormat, credentialsArray) in groupedVcs) {
            when (credentialFormat) {
                FormatType.ldp_vc -> {
                    signablePayloads[credentialFormat] = LdpVpSpecificSigningData(
                        verifiableCredential = credentialsArray as List<String>,
                        id = UUIDGenerator.generateUUID(),
                        holder = ""
                    )
                }
            }
        }

        return signablePayloads
    }


}
