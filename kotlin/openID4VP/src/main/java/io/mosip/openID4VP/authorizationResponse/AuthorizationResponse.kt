package io.mosip.openID4VP.authorizationResponse

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.annotations.SerializedName
import com.google.gson.reflect.TypeToken
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenTypeSerializer

data class AuthorizationResponse(
    @SerializedName("presentation_submission") val presentationSubmission: PresentationSubmission,
    @SerializedName("vp_token") val vpToken: VPTokenType,
    val state: String?,
)

fun AuthorizationResponse.toJsonEncodedMap(): Map<String, Any> {
    val gson: Gson = GsonBuilder()
        .registerTypeAdapter(VPTokenType::class.java, VPTokenTypeSerializer())
        .create()

    val objectAsMap: Map<String, Any> =
        gson.fromJson(gson.toJson(this), object : TypeToken<Map<String, Any>>() {}.type)
    return objectAsMap.filterValues { it != null }
}