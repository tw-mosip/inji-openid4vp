package io.mosip.openID4VP.constants

enum class ContentEncrytionAlgorithm(val value: String) {
    A256GCM("A256GCM");

    companion object {
        fun fromValue(value: String): ContentEncrytionAlgorithm? {
            return entries.find { it.value == value }
        }
    }
}