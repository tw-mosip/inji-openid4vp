package io.mosip.openID4VP.responseModeHandler

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.VPToken

interface ResponseModeBasedHandler {

    fun validate(clientMetadata: ClientMetadata?)

    fun sendAuthorizationResponse(
        vpToken: VPToken,
        authorizationRequest: AuthorizationRequest,
        presentationSubmission: PresentationSubmission,
        state: String?,
        url: String,
    ): String
}