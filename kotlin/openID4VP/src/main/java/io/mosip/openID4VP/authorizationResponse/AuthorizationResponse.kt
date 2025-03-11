package io.mosip.openID4VP.authorizationResponse

import com.fasterxml.jackson.annotation.JsonProperty
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType


data class AuthorizationResponse(
    @JsonProperty("presentation_submission")
    val presentationSubmission: PresentationSubmission,
    @JsonProperty("vp_token")
    val vpToken: VPTokenType,
    val state: String?,
)