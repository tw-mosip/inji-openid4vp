package io.mosip.openID4VP.authorizationRequest.proofJwt.DidHandler

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.mosip.openID4VP.common.Decoder

object DidUtils {
    fun extractKid(jwtToken: String): String? {
        val parts = jwtToken.split(".")
        if (parts.size < 2) return null

        val headerPart = parts[0]
        val decodedHeader = Decoder.decodeBase64ToString(headerPart)
        val jsonis = convertJsonToMap(decodedHeader)
        return jsonis["kid"] as String?
    }

    private fun convertJsonToMap(jsonString: String): Map<String, Any> {
        val mapper = jacksonObjectMapper()
        return mapper.readValue(jsonString, object : TypeReference<Map<String, Any>>() {})
    }

    fun extractPublicKeyMultibase(kid: String, response: String): String? {
        val rootJson = convertJsonToMap(response)
        val didDocument = rootJson["didDocument"] as Map<*, *>
        val verificationMethod = didDocument["verificationMethod"] as? List<Map<String, Any>>

        if (verificationMethod != null) {
            for (method in verificationMethod) {
                val id = method["id"] as? String
                val publicKeyMultibase = method["publicKeyMultibase"] as? String
                if (id == kid && !publicKeyMultibase.isNullOrEmpty()) {
                    return publicKeyMultibase
                }
            }
        }
        return null
    }
}