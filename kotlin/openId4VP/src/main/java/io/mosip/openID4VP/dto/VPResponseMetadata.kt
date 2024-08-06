package io.mosip.openID4VP.dto

import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions

data class VPResponseMetadata (
    val jws: String,
    val signatureAlgorithm: String,
    val publicKey: String,
    val domain: String,
    val sharingTimeoutInMilliseconds: Int,
){
    fun validate(){
        val requiredParams = mapOf(
            "jws" to this.jws,
            "signatureAlgorithm" to this.signatureAlgorithm,
            "publicKey" to this.publicKey,
            "domain" to this.domain,
            "sharingTimeoutInMilliseconds" to this.sharingTimeoutInMilliseconds
        )

        requiredParams.forEach { (key, value) ->
            if(value == "" || value == "null") { throw AuthorizationRequestExceptions.InvalidInput(key) }
        }
    }
}