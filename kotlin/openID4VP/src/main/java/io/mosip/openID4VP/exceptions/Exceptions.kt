package io.mosip.openID4VP.exceptions

sealed class Exceptions {
    class InvalidData(message: String) : Exception(message)
}