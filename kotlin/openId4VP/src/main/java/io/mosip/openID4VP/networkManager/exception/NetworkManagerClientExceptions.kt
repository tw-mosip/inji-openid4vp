package io.mosip.openID4VP.networkManager.exception

sealed class NetworkManagerClientExceptions {
    class NetworkRequestFailedDueToConnectionTimeout: Exception("VP sharing failed due to connection timeout")

    class NetworkRequestFailed(error: String) : Exception("VP sharing failed due to this error - $error")
}