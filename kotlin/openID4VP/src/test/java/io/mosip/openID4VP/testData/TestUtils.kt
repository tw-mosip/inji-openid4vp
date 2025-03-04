package io.mosip.openID4VP.testData

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_METADATA
import io.mosip.openID4VP.common.ClientIdScheme
import io.mosip.openID4VP.testData.JWTUtil.Companion.createJWT
import kotlinx.serialization.json.JsonObject
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

fun createUrlEncodedData(
    requestParams: Map<String, String?>,
    verifierSentAuthRequestByReference: Boolean? = false,
    clientIdScheme: ClientIdScheme,
    applicableFields: List<String>? = null
): String {
    val paramList = when (verifierSentAuthRequestByReference) {
        true -> authRequestParamsByReference
        else -> applicableFields ?: authorisationRequestListToClientIdSchemeMap[clientIdScheme]!!
    }
    val authorizationRequestParam = createAuthorizationRequest(paramList, requestParams ) as Map<String, Any>

    val charset = StandardCharsets.UTF_8.toString()

    val queryString = authorizationRequestParam.entries.joinToString("&") {
        "${it.key}=${it.value}"
    }
    val urlEncodedQueryParameters = URLEncoder.encode(queryString, charset)
    return "openid4vp://authorize?$urlEncodedQueryParameters"

}

fun createAuthorizationRequestObject(
    clientIdScheme: ClientIdScheme,
    authorizationRequestParams: Map<String, String>,
    applicableFields: List<String>? = null,
    addValidSignature: Boolean? = true,
    jwtHeader: JsonObject? = null,
    isPresentationDefinitionUriPresent: Boolean? = false
): Any {
    val mapper = jacksonObjectMapper()
    val paramList = applicableFields ?: authorisationRequestListToClientIdSchemeMap[clientIdScheme]!!
    return createAuthorizationRequest(paramList, authorizationRequestParams).let { authRequestParam ->

        val param = if(isPresentationDefinitionUriPresent != true)
            authRequestParam + clientMetadataPresentationDefinitionMap
        else
            authRequestParam + mapOf(
                CLIENT_METADATA.value to clientMetadataMap
            )
        when (clientIdScheme) {
            ClientIdScheme.DID -> createJWT(param, addValidSignature!!, jwtHeader)
            else -> mapper.writeValueAsString(param)
        }
    }
}

private fun createAuthorizationRequest(
    paramList: List<String>,
    requestParams: Map<String, String?>
): MutableMap<String, String?> {
    val authorizationRequestParam = paramList
        .filter { requestParams.containsKey(it) }
        .associateWith { requestParams[it] }
        .toMutableMap()
    return authorizationRequestParam
}