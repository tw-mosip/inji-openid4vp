package io.mosip.openID4VP.dto.VPResponseMetadata.types

import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.validateField
import io.mosip.openID4VP.dto.VPResponseMetadata.VPResponseMetadata

private val className = LdpVPResponseMetadata::class.simpleName!!


data class LdpVPResponseMetadata(
    val jws: String,
    val signatureAlgorithm: String,
    val publicKey: String,
    val domain: String,
) : VPResponseMetadata {
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
                    fieldPath = listOf("vp response metadata", key),
                    className = className,
                    fieldType = key::class.simpleName
                )
            }
        }
    }
}