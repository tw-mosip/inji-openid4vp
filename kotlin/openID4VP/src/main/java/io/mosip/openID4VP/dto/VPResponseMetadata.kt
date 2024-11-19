package io.mosip.openID4VP.dto

import io.mosip.openID4VP.common.Logger

private val className = VPResponseMetadata::class.simpleName!!
data class VPResponseMetadata(
    val jws: String,
    val signatureAlgorithm: String,
    val publicKey: String,
    val domain: String,
) {
    fun validate() {
        val requiredParams = mapOf(
            "jws" to this.jws,
            "signatureAlgorithm" to this.signatureAlgorithm,
            "publicKey" to this.publicKey,
            "domain" to this.domain,
        )

        requiredParams.forEach { (key, value) ->
            if (value == "" || value == "null") {
                throw Logger.handleException(
                    exceptionType = "InvalidInput",
                    fieldPath = listOf("vp response metadata",key),
                    className = className
                )
            }
        }
    }
}