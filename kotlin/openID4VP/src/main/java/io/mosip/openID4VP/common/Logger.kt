package io.mosip.openID4VP.common

import android.util.Log
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.authorizationResponse.exception.AuthorizationResponseExceptions

//TODO: Log - use common logger for android and java environment
object Logger {
    private var traceabilityId: String? = null

    fun setTraceabilityId(traceabilityId: String) {
        this.traceabilityId = traceabilityId
    }

    fun getLogTag(className: String): String {
        return "INJI-OpenID4VP : class name - $className | traceID - ${this.traceabilityId ?: ""}"
    }

    fun error(logTag: String, exception: Exception) {
        println("exception $exception")
        Log.e(logTag, exception.message?:"Exception occurred - $exception")
    }

    fun handleException(
        exceptionType: String,
        message: String? = null,
        fieldPath: List<String>? = null,
        className: String,
        fieldType: Any? = null,
    ): Exception {
        var fieldPathAsString: String = ""
        fieldPath?.let {
            fieldPathAsString = fieldPath.joinToString("->")
        }
        var exception = Exception()
        when (exceptionType) {
            "MissingInput" -> exception =
                AuthorizationRequestExceptions.MissingInput(fieldPath = fieldPathAsString)

            "InvalidInput" -> exception =
                AuthorizationRequestExceptions.InvalidInput(
                    fieldPath = fieldPathAsString,
                    fieldType = fieldType
                )

            "InvalidInputPattern" -> exception =
                AuthorizationRequestExceptions.InvalidInputPattern(fieldPath = fieldPathAsString)

            "InvalidQueryParams" -> exception =
                AuthorizationRequestExceptions.InvalidQueryParams(message = message ?: "")

            "InvalidVerifierRedirectUri" -> exception =
                AuthorizationRequestExceptions.InvalidVerifierRedirectUri(message = message ?: "")

            "JsonEncodingFailed" -> exception = AuthorizationRequestExceptions.JsonEncodingFailed(
                fieldPath = fieldPathAsString, message = message ?: ""
            )

            "InvalidVerifierClientID" -> exception =
                AuthorizationRequestExceptions.InvalidVerifierClientID()

            "InvalidLimitDisclosure" -> exception =
                AuthorizationRequestExceptions.InvalidLimitDisclosure()

            "DeserializationFailure" -> exception =
                AuthorizationRequestExceptions.DeserializationFailure(
                    fieldPath = fieldPathAsString,
                    message = message ?: ""
                )

            "UnsupportedFormatOfLibrary" -> exception =
                AuthorizationResponseExceptions.UnsupportedCredentialFormat(
                    message = message
                        ?: "Provided credential format is not supported by the library"
                )

            "UnsupportedResponseType" -> exception =
                AuthorizationResponseExceptions.UnsupportedResponseType(
                    message = message ?: "Provided response_type is not supported by the library"
                )

            "UnsupportedResponseMode" -> exception =
                AuthorizationResponseExceptions.UnsupportedResponseMode(
                    message = message ?: "Provided response_mode is not supported by the library"
                )

            "access_denied" -> exception =
                AuthorizationResponseExceptions.AccessDenied(
                    message = message ?: "Provided response_mode is not supported by the library"
                )

            "" -> exception =
                Exception("An unexpected exception occurred: exception type: $exceptionType")
        }
        this.error(getLogTag(className), exception)
        return exception
    }
}