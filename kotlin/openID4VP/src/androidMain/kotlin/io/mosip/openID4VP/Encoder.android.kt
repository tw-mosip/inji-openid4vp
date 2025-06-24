package io.mosip.openID4VP

import android.util.Base64.NO_PADDING
import android.util.Base64.encodeToString

actual fun encodeToBase64Url(data: ByteArray): String {
    val base64 = encodeToString(data, NO_PADDING)
    return base64
}