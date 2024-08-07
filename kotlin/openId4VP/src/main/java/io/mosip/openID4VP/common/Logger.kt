package io.mosip.openID4VP.common

import android.util.Log
import kotlin.math.log

object Logger {
    private var traceabilityId: String? = null

    fun setTraceability(traceabilityId: String?){
        this.traceabilityId = traceabilityId
    }
    fun getLogTag(className: String): String {
        return "INJI-OpenID4VP : class name - $className | traceID - ${this.traceabilityId ?: ""}"
    }

    fun error(logTag: String, exception: Exception){
        Log.e(logTag, exception.message!!)
    }
}