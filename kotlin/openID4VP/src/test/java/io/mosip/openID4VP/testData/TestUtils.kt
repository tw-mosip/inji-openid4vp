package io.mosip.openID4VP.testData

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.mosip.openID4VP.authorizationRequest.ClientIdScheme
import io.mosip.openID4VP.testData.JWTUtil.Companion.createJWT
import io.mosip.openID4VP.testData.JWTUtil.Companion.encodeB64
import kotlinx.serialization.json.JsonObject
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.Base64

fun createEncodedAuthorizationRequest(
    requestParams: Map<String, String?>,
    verifierSentAuthRequestByReference: Boolean? = false,
    clientIdScheme: ClientIdScheme,
    applicableFields: List<String>? = null
): String {
    val paramList = when (verifierSentAuthRequestByReference) {
        true -> authRequestParamsByReference
        else -> applicableFields ?: authorisationRequestListToClientIdSchemeMap[clientIdScheme]!!
    }
    val authorizationRequestParam = createAuthorizationRequest(paramList, requestParams)
    val charset = StandardCharsets.UTF_8.toString()

    val encodedParams = authorizationRequestParam.entries.joinToString("&") {
        "${URLEncoder.encode(it.key, charset)}=${URLEncoder.encode(it.value, charset)}"
    }
    return "OPENID4VP://authorize?$encodedParams"

}

fun createAuthorizationRequestObject(
    clientIdScheme: ClientIdScheme,
    authorizationRequestParams: Map<String, String>,
    applicableFields: List<String>? = null,
    addValidSignature: Boolean? = true,
    jwtHeader: JsonObject? = null
): String {
    val mapper = jacksonObjectMapper()
    val paramList = applicableFields ?: authorisationRequestListToClientIdSchemeMap[clientIdScheme]!!
    return createAuthorizationRequest(paramList, authorizationRequestParams).let { authRequestParam ->
        when (clientIdScheme) {
            ClientIdScheme.DID -> createJWT(mapper, authRequestParam, addValidSignature!!, jwtHeader)
            else -> encodeB64(mapper.writeValueAsString(authRequestParam))
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