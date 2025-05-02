package io.mosip.openID4VP.authorizationResponse.authenticationContainer.types

import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.validateField
import io.mosip.openID4VP.authorizationResponse.authenticationContainer.AuthenticationContainer

private val className = LdpAuthenticationContainer::class.simpleName!!

data class LdpAuthenticationContainer(
    val jws: String,
    val signatureAlgorithm: String,
    val publicKey: String,
    val domain: String,
) : AuthenticationContainer {
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
                    fieldPath = listOf("vp_response_metadata",key),
                    className = className,
                    fieldType = key::class.simpleName
                )
            }
        }
    }
}