package io.mosip.openID4VP.models

import com.google.gson.annotations.SerializedName

data class PresentationDefinition (
    @SerializedName("id") val id: String,
    @SerializedName("input_descriptors") val inputDescriptors: ArrayList<InputDescriptors>
)
data class InputDescriptors (
    @SerializedName("id") val id: String,
    @SerializedName("name") val name: String?,
    @SerializedName("purpose") val purpose: String?,
    @SerializedName("format") val format: Format,
    @SerializedName("constraints") val constraints: Constraints?
)
data class Format (
    @SerializedName("ldp_vc" ) val ldpVc: LdpVc?
)
data class LdpVc (
    @SerializedName("proof_type" ) val proofType : ArrayList<String>
)
data class Constraints (
    @SerializedName("limit_disclosure") val limitDisclosure: LimitDisclosureType?,
    @SerializedName("fields" ) val fields: ArrayList<Fields>?
)

enum class LimitDisclosureType(val value: String) {
    REQUIRED("required"),
    PREFERRED("preferred")
}
data class Fields (
    @SerializedName("path") val path: ArrayList<String>,
    @SerializedName("filter") val filter: Filter?
)
data class Filter (
    @SerializedName("type") var type: String? = null,
    @SerializedName("pattern") var pattern: String? = null
)