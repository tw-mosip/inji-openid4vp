package io.mosip.openID4VP.authorizationResponse.models

import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.common.Logger
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

private val className = AuthorizationResponse::class.java.simpleName
@Serializable
class AuthorizationResponse(
    val vpToken: VPTokenType,
    val presentationSubmission: PresentationSubmission) {

    fun encodedItems(): Map<String, String> {
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
            encodedPresentationSubmission =
                Json.encodeToString(presentationSubmission)
        } catch (exception: Exception) {
            throw Logger.handleException(
                exceptionType = "JsonEncodingFailed",
                message = exception.message,
                fieldPath = listOf("presentation_submission"),
                className = className
            )
        }
        return mapOf(
            "vp_token" to encodedVPToken,
            "presentation_submission" to encodedPresentationSubmission,
        )
    }
}
