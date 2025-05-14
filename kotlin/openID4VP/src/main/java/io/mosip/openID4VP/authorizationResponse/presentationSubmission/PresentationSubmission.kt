package io.mosip.openID4VP.authorizationResponse.presentationSubmission

import com.google.gson.annotations.SerializedName


data class PresentationSubmission(
    val id: String,
    @SerializedName("definition_id") val definitionId: String,
    @SerializedName("descriptor_map") val descriptorMap: List<DescriptorMap>
)