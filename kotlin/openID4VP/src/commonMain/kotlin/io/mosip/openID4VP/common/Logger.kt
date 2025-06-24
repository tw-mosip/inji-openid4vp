package io.mosip.openID4VP.common

import java.util.logging.Level
import java.util.logging.Logger as JULogger
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.jwt.exception.JWEException
import io.mosip.openID4VP.jwt.exception.JWSException
import io.mosip.openID4VP.exceptions.Exceptions

//TODO: Log - use common logger for android and Java env
object Logger {

    private var traceabilityId: String? = null

    fun setTraceabilityId(traceabilityId: String) {
        this.traceabilityId = traceabilityId
    }

    fun getLogTag(className: String): String {
        return "INJI-OpenID4VP : class name - $className | traceID - ${this.traceabilityId ?: ""}"
    }

    private fun getLogger(className: String): JULogger {
        return JULogger.getLogger(className)
    }

    fun error(logTag: String, exception: Exception, className: String? = "") {
        val logger = getLogger(className ?: "UnknownClass")
        val message = "$logTag : ${exception.message}"
        logger.log(Level.SEVERE, message, exception)
    }

    fun handleException(
        exceptionType: String,
        message: String? = null,
        fieldPath: List<String>? = null,
        className: String,
        fieldType: Any? = null
    ): Exception {
        var fieldPathAsString = ""
        fieldPath?.let {
            fieldPathAsString = fieldPath.joinToString("->")
        }
        val exception: Exception = when (exceptionType) {

            "InvalidInput" -> Exceptions.InvalidInput(
                fieldPath = fieldPathAsString,
                fieldType = fieldType
            )
            "DeserializationFailure" -> AuthorizationRequestExceptions.DeserializationFailure(
                fieldPath = fieldPathAsString,
                message = message ?: ""
            )
            "JsonEncodingFailed" -> AuthorizationRequestExceptions.JsonEncodingFailed(
                fieldPath = fieldPathAsString, message = message ?: ""
            )
            "MissingInput" -> Exceptions.MissingInput(fieldPath = fieldPathAsString, message = message ?: "")

            "InvalidInputPattern" -> AuthorizationRequestExceptions.InvalidInputPattern(fieldPath = fieldPathAsString)

            "InvalidQueryParams" -> AuthorizationRequestExceptions.InvalidQueryParams(message = message ?: "")

            "InvalidVerifier" -> AuthorizationRequestExceptions.InvalidVerifier(message = message ?: "")

            "InvalidLimitDisclosure" -> AuthorizationRequestExceptions.InvalidLimitDisclosure()

            "InvalidData" -> Exceptions.InvalidData(message = message ?: "")

            "PublicKeyResolutionFailed" -> JWSException.PublicKeyResolutionFailed(message = message ?: "")

            "KidExtractionFailed" -> JWSException.KidExtractionFailed(message = message ?: "")

            "PublicKeyExtractionFailed" -> JWSException.PublicKeyExtractionFailed(message = message ?: "")

            "InvalidSignature" -> JWSException.InvalidSignature(message = message ?: "")

            "VerificationFailure" -> JWSException.VerificationFailure(message = message ?: "")

            //JWK Algorithm Exceptions

            "UnsupportedKeyExchangeAlgorithm" ->  JWEException.UnsupportedKeyExchangeAlgorithm()

            "JweEncryptionFailure" ->  JWEException.JweEncryptionFailure()

            else -> Exception("An unexpected exception occurred: exception type: $exceptionType")
        }
        this.error(getLogTag(className), exception)
        return exception
    }
}