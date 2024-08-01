package io.mosip.openID4VP.authorizationResponse.presentationSubmission

data class PresentationSubmission(
    val id: String,
    val definitionId: String,
    val descriptorMap: List<DescriptorMap>
)