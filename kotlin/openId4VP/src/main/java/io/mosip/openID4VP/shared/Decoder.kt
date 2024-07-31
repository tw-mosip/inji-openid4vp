package io.mosip.openID4VP.shared

import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import org.apache.commons.codec.binary.Base64
import java.nio.charset.StandardCharsets

class Decoder {
    companion object {
        fun decodeBase64ToString(encodedData: String): String {
            when {
                encodedData.isEmpty() -> throw AuthorizationRequestExceptions.InvalidInput("encoded data")
                else -> {
                    try {
                        val decodedBytes: ByteArray = Base64.decodeBase64(encodedData.toByteArray(StandardCharsets.UTF_8))
                        return String(decodedBytes, StandardCharsets.UTF_8)
                    } catch (e: Exception) {
                        throw AuthorizationRequestExceptions.DecodingException("Error occurred while decoding data: ${e.message}") // More specific exception type
                    }
                }
            }
        }
    }
}