package io.mosip.openID4VP.common

actual fun decodeFromBase64Url(content: String): ByteArray {
    return java.util.Base64.getUrlDecoder().decode(content.toByteArray())
}