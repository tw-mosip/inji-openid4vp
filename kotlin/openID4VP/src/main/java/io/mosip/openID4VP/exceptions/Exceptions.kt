package io.mosip.openID4VP.exceptions

sealed class Exceptions {
    class InvalidData(message: String) : Exception(message)

    class MissingInput(fieldPath: String, message: String) :  Exception(
        if (fieldPath.isNotEmpty()) {
            "Missing Input: $fieldPath param is required"
        } else {
            message
        }
    )
}