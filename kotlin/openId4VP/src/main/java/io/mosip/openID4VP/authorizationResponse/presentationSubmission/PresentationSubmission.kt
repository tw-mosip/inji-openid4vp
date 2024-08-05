package io.mosip.openID4VP.authorizationResponse.presentationSubmission

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class PresentationSubmission(
    val id: String,
    @SerialName("definition_id")
    val definitionId: String,
    @SerialName("descriptor_map")
    val descriptorMap: List<DescriptorMap>
)