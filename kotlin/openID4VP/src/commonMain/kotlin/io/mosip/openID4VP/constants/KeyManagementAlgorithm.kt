package io.mosip.openID4VP.constants

enum class KeyManagementAlgorithm(val value: String) {
    ECDH_ES("ECDH-ES");

    companion object {
        fun fromValue(value: String): KeyManagementAlgorithm? {
            return entries.find { it.value == value }
        }
    }
}