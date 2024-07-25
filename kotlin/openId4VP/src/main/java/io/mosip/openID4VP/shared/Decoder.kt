package io.mosip.openID4VP.shared

import android.util.Base64
import io.mosip.openID4VP.exception.AuthorizationRequestExceptions
import java.nio.charset.Charset

class Decoder {
    companion object {
        fun decodeBase64ToString(encodedData: String): String {
            when {
                encodedData.isEmpty() -> throw IllegalArgumentException("Error occurred while decoding data: input cannot be empty")
                else -> {
                    try {
                        val decodedByteArray: ByteArray = Base64.decode(encodedData, Base64.DEFAULT)
                        return String(decodedByteArray, Charset.forName("UTF-8"))
                    } catch (e: Exception) {
                        throw AuthorizationRequestExceptions.DecodingException("Error occurred while decoding data: ${e.message}") // More specific exception type
                    }
                }
            }
        }
    }
}