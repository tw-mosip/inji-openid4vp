package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.VPTokenForSigning
import io.mosip.openID4VP.common.FormatType
import io.mosip.openID4VP.common.Logger
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

fun encodeVPTokenForSigning(vpTokensForSigning: Map<FormatType, VPTokenForSigning>): Map<String,String>{
    try {
        val formatted = mutableMapOf<String, String>()

        for ((key, value) in vpTokensForSigning) {
            val encodedContent = Json.encodeToString(value)
            formatted[key.value] = encodedContent
        }

        return formatted
    } catch (exception: Exception) {
        throw Logger.handleException(
            exceptionType = "JsonEncodingFailed",
            message = exception.message,
            fieldPath = listOf("vp_token_for_signing"),
            className = "AuthorizationResponseUtils"
        )
    }
}