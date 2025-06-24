package io.mosip.openID4VP

actual fun decodeBase64Data(content: String): ByteArray {
    return java.util.Base64.getUrlDecoder().decode(content.toByteArray())
}