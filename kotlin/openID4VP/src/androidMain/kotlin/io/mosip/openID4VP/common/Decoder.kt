package io.mosip.openID4VP.common

import android.annotation.SuppressLint
import android.util.Base64

actual fun decodeFromBase64Url(content: String): ByteArray {
    return try {
        javaBase64UrlDecode(content)
    } catch (_: Throwable) {
        androidBase64UrlDecode(content)
    }
}

@SuppressLint("NewApi")
private fun javaBase64UrlDecode(content: String): ByteArray =
    java.util.Base64.getUrlDecoder().decode(content.toByteArray())

private fun androidBase64UrlDecode(content: String): ByteArray {
    return Base64.decode(content, Base64.DEFAULT or Base64.URL_SAFE)
}