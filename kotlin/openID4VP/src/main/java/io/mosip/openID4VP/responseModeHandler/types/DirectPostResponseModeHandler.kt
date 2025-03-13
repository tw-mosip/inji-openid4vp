package io.mosip.openID4VP.responseModeHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.VPToken
import io.mosip.openID4VP.common.encodeToJsonString
import io.mosip.openID4VP.networkManager.CONTENT_TYPE.APPLICATION_FORM_URL_ENCODED
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandler

private val className = DirectPostResponseModeHandler::class.simpleName!!


class DirectPostResponseModeHandler: ResponseModeBasedHandler() {
    override fun validate(clientMetadata: ClientMetadata?) {
        return
    }

    override fun sendAuthorizationResponse(
        vpToken: VPToken,
        authorizationRequest: AuthorizationRequest,
        presentationSubmission: PresentationSubmission,
        state: String?,
        url: String
    ): String {
        val encodedVPToken = encodeToJsonString(vpToken, "vp_token", className )
        val encodedPresentationSubmission = encodeToJsonString(presentationSubmission, "presentation_submission", className)
        val bodyParams = mapOf(
            "vp_token" to encodedVPToken,
            "presentation_submission" to encodedPresentationSubmission,
        ).let { baseParams ->
            state?.let { baseParams + mapOf("state" to it) } ?: baseParams
        }
        val response = sendHTTPRequest(
            url = url,
            method = HTTP_METHOD.POST,
            bodyParams = bodyParams,
            headers = mapOf("Content-Type" to APPLICATION_FORM_URL_ENCODED.value)
        )
        return response["body"].toString()
    }
}