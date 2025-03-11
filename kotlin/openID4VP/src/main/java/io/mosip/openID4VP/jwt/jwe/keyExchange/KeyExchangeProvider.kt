package io.mosip.openID4VP.jwt.jwe.keyExchange

import com.nimbusds.jose.JWEAlgorithm
import io.mosip.openID4VP.common.Logger

private val className = KeyExchangeProvider::class.simpleName!!
object KeyExchangeProvider {
    fun getAlgorithm(algorithm: String): JWEAlgorithm = when (algorithm) {
        "ECDH-ES" -> JWEAlgorithm.ECDH_ES
        else -> throw Logger.handleException(
            exceptionType = "UnsupportedKeyExchangeAlgorithm",
            className = className
        )
    }
}