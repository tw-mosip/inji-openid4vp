package io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.mdoc

import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.validateField

private val className = DeviceAuthentication::class.simpleName!!

data class DeviceAuthentication(
    val signature: String,
    val algorithm: String
) {
    fun validate() {
        val requiredParams = mapOf("signature" to signature, "algorithm" to algorithm)
        requiredParams.forEach { (key, value) ->
            require(value != "null" && validateField(value, "String")) {
                throw Logger.handleException(
                    exceptionType = "InvalidInput",
                    fieldPath = listOf("mdoc_vp_token_signing_result","device_authentication", key),
                    className = className,
                    fieldType = key
                )
            }
        }
    }
}