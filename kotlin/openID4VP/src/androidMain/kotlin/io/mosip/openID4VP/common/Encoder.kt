package io.mosip.openID4VP.common

import android.annotation.SuppressLint
import android.util.Base64.NO_PADDING
import android.util.Base64.encodeToString
import java.util.Base64.getUrlEncoder

actual fun encodeToBase64Url(data: ByteArray): String {
    return try {
        javaBase64UrlEncode(data)
    } catch (_: Throwable) {
        androidBase64UrlEncode(data)
    }
}

@SuppressLint("NewApi")
private fun javaBase64UrlEncode(data: ByteArray): String =
    getUrlEncoder().withoutPadding().encodeToString(data)

private fun androidBase64UrlEncode(data: ByteArray): String {
    val base64 = encodeToString(data, NO_PADDING)
    return base64
}