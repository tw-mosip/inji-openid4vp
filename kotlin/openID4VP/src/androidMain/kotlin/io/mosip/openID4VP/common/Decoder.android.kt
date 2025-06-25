package io.mosip.openID4VP.common

actual fun decodeBase64Data(content: String): ByteArray {
    var base64: String = content.replace('-', '+').replace('_', '/')
    when (base64.length % 4) {
        2 -> base64 += "=="
        3 -> base64 += "="
        else -> {}
    }

    return android.util.Base64.decode(base64, android.util.Base64.DEFAULT)
}