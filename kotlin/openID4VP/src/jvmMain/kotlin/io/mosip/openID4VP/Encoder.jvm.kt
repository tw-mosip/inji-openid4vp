package io.mosip.openID4VP

import java.util.Base64.getUrlEncoder

actual fun encodeToBase64Url(data: ByteArray): String {
    return  getUrlEncoder().encodeToString(data)
}