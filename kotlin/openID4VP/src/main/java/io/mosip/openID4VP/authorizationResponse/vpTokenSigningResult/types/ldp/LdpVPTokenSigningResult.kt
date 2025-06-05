package io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp

import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.validateField

private val className = LdpVPTokenSigningResult::class.simpleName!!

data class LdpVPTokenSigningResult(
    val jws: String,
    val signatureAlgorithm: String,
    val publicKey: String,
    val domain: String,
) : VPTokenSigningResult {
    fun validate() {
        val requiredParams = mapOf(
            "jws" to this.jws,
            "signatureAlgorithm" to this.signatureAlgorithm,
            "publicKey" to this.publicKey,
            "domain" to this.domain,
        )

        requiredParams.forEach { (key, value) ->
            require(value != "null" && validateField(value, "String")) {
                throw Logger.handleException(
                    exceptionType = "InvalidInput",
                    fieldPath = listOf("ldp_vp_token_signing_result", key),
                    className = className,
                    fieldType = key::class.simpleName
                )
            }
        }
    }
}

//data class LdpVPTokenSigningResult(
//    val jws: String
//) : VPTokenSigningResult {
//    fun validate() {
//        require(jws != "null" && validateField(jws, "String")) {
//            throw Logger.handleException(
//                exceptionType = "InvalidInput",
//                fieldPath = listOf("ldp_vp_token_signing_result", jws),
//                className = className,
//                fieldType = jws::class.simpleName
//            )
//        }
//    }
//}