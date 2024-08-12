package io.mosip.openID4VP.common

import android.util.Log
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions

object Logger {
    private var traceabilityId: String? = null

    fun setTraceability(traceabilityId: String?) {
        this.traceabilityId = traceabilityId
    }

    fun getLogTag(className: String): String {
        return "INJI-OpenID4VP : class name - $className | traceID - ${this.traceabilityId ?: ""}"
    }

    fun error(logTag: String, exception: Exception) {
        Log.e(logTag, exception.message!!)
    }

    fun handleException(
        exceptionType: String, parentField: String, currentField: String, className: String
    ): Exception {
        val fieldPath = "$parentField : $currentField"
        var exception = Exception()
        when(exceptionType){
            "MissingInput" -> exception = AuthorizationRequestExceptions.MissingInput(fieldPath)
            "InvalidInput" -> exception = AuthorizationRequestExceptions.InvalidInput(fieldPath)
            "InvalidInputPattern" -> exception = AuthorizationRequestExceptions.InvalidInputPattern(fieldPath)
        }
        this.error(getLogTag(className), exception)
        return exception
    }
}