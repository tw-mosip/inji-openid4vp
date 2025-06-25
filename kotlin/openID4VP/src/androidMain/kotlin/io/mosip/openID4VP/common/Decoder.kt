package io.mosip.openID4VP.common

import android.util.Base64

actual fun decodeBase64Data(content: String): ByteArray {
    return Base64.decode(content, Base64.DEFAULT or Base64.URL_SAFE)
}