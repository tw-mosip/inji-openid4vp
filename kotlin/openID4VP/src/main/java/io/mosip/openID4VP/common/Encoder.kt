package io.mosip.openID4VP.common


import android.annotation.SuppressLint
import android.os.Build
import android.util.Base64.*
import io.mosip.openID4VP.common.BuildConfig.getVersionSDKInt
import io.mosip.openID4VP.common.BuildConfig.isAndroid
import java.util.Base64.*

object Encoder {

    fun encodeToBase64Url(data: ByteArray): String {
        return if (isAndroid()) {
            if (getVersionSDKInt() >= Build.VERSION_CODES.O) {
                javaBase64UrlEncode(data)
            } else {
                androidBase64UrlEncode(data)
            }
        } else {
            javaBase64UrlEncode(data)
        }
    }

    @SuppressLint("NewApi")
    private fun javaBase64UrlEncode(data: ByteArray): String =
        getUrlEncoder().encodeToString(data)

    private fun androidBase64UrlEncode(data: ByteArray): String {
        val base64 = encodeToString(data, NO_PADDING)
        return base64
    }
}
