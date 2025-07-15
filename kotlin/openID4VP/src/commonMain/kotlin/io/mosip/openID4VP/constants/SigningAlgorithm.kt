package io.mosip.openID4VP.constants

enum class SigningAlgorithm(value: String) {
    EdDSA("EdDSA"),
    ES256("ES256"),
    RS256("RS256"),
    PS256("PS256");

    val value: String = value

    companion object {

        fun fromValue(value: String): SigningAlgorithm? {
            return entries.find { it.value == value }
        }
    }
}