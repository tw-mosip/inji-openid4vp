package io.mosip.openID4VP.authorizationResponse

import com.fasterxml.jackson.annotation.JsonProperty
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.common.encodeToJsonString

private val className: String = AuthorizationResponse::class.simpleName!!

data class AuthorizationResponse(
    @JsonProperty("presentation_submission")
    val presentationSubmission: PresentationSubmission,
    @JsonProperty("vp_token")
    val vpToken: VPTokenType,
    val state: String?,
)

fun AuthorizationResponse.toJsonEncodedMap(): Map<String, String> {
    return buildMap {
        put("vp_token", encodeToJsonString<VPTokenType>(vpToken, "vp_token", className))
        put(
            "presentation_submission",
            encodeToJsonString<PresentationSubmission>(
                presentationSubmission,
                "presentation_submission",
                className
            )
        )
        state?.let<String, Unit> { put("state", it) }
    }
}
