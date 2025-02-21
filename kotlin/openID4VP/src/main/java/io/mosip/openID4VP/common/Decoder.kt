package io.mosip.openID4VP.common

import android.annotation.SuppressLint
import android.os.Build
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.common.BuildConfig.getVersionSDKInt
import io.mosip.openID4VP.common.BuildConfig.isAndroid
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


    fun decodeBase64Data(content: String): ByteArray {
        val decodedBase64ByteArray =  if (isAndroid()) {
            if( getVersionSDKInt() >= Build.VERSION_CODES.O){
                javaBase64UrlDecode(content)
            } else {
                androidBase64UrlDecode(content)
            }
        } else {
            javaBase64UrlDecode(content)
        }
        return decodedBase64ByteArray
        //return String(decodedBase64ByteArray, StandardCharsets.UTF_8)
    }

    @SuppressLint("NewApi")
    private fun javaBase64UrlDecode(content: String): ByteArray =
        java.util.Base64.getUrlDecoder().decode(content.toByteArray())

    private fun androidBase64UrlDecode(content: String): ByteArray {
        var base64: String = content.replace('-', '+').replace('_', '/')
        when (base64.length % 4) {
            2 -> base64 += "=="
            3 -> base64 += "="
            else -> {}
        }

        return android.util.Base64.decode(base64, android.util.Base64.DEFAULT)
    }
}