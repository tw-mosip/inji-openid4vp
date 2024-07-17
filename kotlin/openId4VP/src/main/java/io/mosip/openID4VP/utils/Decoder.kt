package io.mosip.openID4VP.utils

import android.util.Base64
import java.nio.charset.Charset

class Decoder {
    fun decodeBase64ToString(encodedData: String) : String{
        val decodedByteArray: ByteArray = Base64.decode(encodedData, Base64.DEFAULT)
        val decodedString = String(decodedByteArray, Charset.forName("UTF-8"))

        return decodedString
    }
}