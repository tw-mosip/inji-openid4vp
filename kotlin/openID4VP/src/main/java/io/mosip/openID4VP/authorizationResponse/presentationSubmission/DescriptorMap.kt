package io.mosip.openID4VP.authorizationResponse.presentationSubmission

import kotlinx.serialization.Serializable

@Serializable
data class DescriptorMap(
    val id: String,
    val format: String,
    val path: String,
)