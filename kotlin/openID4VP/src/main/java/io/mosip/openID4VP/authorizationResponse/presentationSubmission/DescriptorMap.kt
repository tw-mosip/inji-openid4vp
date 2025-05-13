package io.mosip.openID4VP.authorizationResponse.presentationSubmission

import com.google.gson.annotations.SerializedName

data class DescriptorMap(
    val id: String,
    val format: String,
    val path: String,
    @SerializedName("path_nested")
    val pathNested: PathNested? = null,
)

data class PathNested(
    val id: String,
    val format: String,
    val path: String,
)