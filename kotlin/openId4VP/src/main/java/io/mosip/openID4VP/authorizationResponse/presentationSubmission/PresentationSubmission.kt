package io.mosip.openID4VP.authorizationResponse.presentationSubmission

import kotlinx.serialization.Serializable

@Serializable
data class PresentationSubmission(
    val id: String,
    val definitionId: String,
    val descriptorMap: List<DescriptorMap>
)