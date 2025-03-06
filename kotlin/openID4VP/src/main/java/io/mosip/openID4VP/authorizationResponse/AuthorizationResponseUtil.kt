package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationResponse.jwe.JWEProcessor
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.VPToken
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.ResponseMode.DIRECT_POST
import io.mosip.openID4VP.common.ResponseMode.DIRECT_POST_JWT
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json


private val className = AuthorizationResponse::class.simpleName!!

fun createAuthorizationResponseBody(
    vpToken: VPToken,
    authorizationRequest: AuthorizationRequest,
    presentationSubmission: PresentationSubmission,
    state: String?
): Map<String, String> {

    val encodedVPToken = encode(vpToken, "vp_token")
    val encodedPresentationSubmission = encode(presentationSubmission, "presentation_submission")
    val bodyParams = mapOf(
        "vp_token" to encodedVPToken,
        "presentation_submission" to encodedPresentationSubmission,
    ).let { baseParams ->
        state?.let { baseParams + mapOf("state" to it) } ?: baseParams
    }
    val clientMetadata = authorizationRequest.clientMetadata as ClientMetadata

    return when (authorizationRequest.responseMode) {
        DIRECT_POST.value -> {
            bodyParams
        }
        DIRECT_POST_JWT.value -> {
            val encryptedBody = JWEProcessor(clientMetadata).generateEncryptedResponse(bodyParams)
            mapOf("response" to encryptedBody)
        }
        else -> {
            throw Logger.handleException(
                exceptionType = "InvalidData",
                className = className,
                message = "Given response_mode is not supported"
            )
        }

    }
}

fun createDescriptorMap(verifiableCredentials: Map<String, List<String>>): MutableList<DescriptorMap> {
    var pathIndex = 0
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
    return descriptorMap
}

inline fun <reified T> encode(data: T, fieldName: String): String {
    try {
        return Json.encodeToString(data)
    } catch (exception: Exception) {
        throw Logger.handleException(
            exceptionType = "JsonEncodingFailed",
            message = exception.message,
            fieldPath = listOf(fieldName),
            className = AuthorizationResponse::class.simpleName!!
        )
    }
}