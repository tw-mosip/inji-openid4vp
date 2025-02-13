package io.mosip.openID4VP.authorizationResponse.models

import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.common.Logger
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

private val className = AuthorizationResponseModel::class.java.simpleName
//TODO: To be renamed to AuthorizationResponse once the old AuthResponse class is deleted
@Serializable
class AuthorizationResponseModel(
    val vpToken: VPTokenType,
    val presentationSubmission: PresentationSubmission) {
//    fun  encodedItem

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
