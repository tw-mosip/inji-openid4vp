package io.mosip.openID4VP.common

import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import org.apache.commons.codec.binary.Base64
import java.nio.charset.StandardCharsets

private val className = Decoder::class.simpleName!!
object Decoder {
    private val logTag = Logger.getLogTag(this::class.simpleName!!)

    fun decodeBase64ToString(encodedData: String): String {
        when {
            encodedData.isEmpty() -> throw Logger.handleException(
                exceptionType = "InvalidInput",
                fieldPath = listOf("encoded data"),
                className = className,
                fieldType = encodedData::class.simpleName
            )
            else -> {
                try {
                    val decodedBytes: ByteArray = Base64.decodeBase64(encodedData)
                    return String(decodedBytes, StandardCharsets.UTF_8)
                } catch (e: Exception) {
                    val exception =
                        AuthorizationRequestExceptions.DecodingException("Error occurred while decoding data: ${e.message}")
                    Logger.error(logTag, exception)
                    throw exception
                }
            }
        }
    }
}