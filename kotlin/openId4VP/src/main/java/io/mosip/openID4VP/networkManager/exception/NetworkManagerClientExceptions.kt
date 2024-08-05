package io.mosip.openID4VP.networkManager.exception

class NetworkManagerClientExceptions {
    class NetworkRequestFailedDueToConnectionTimeout: Exception("VP sharing failed due to connection timeout")

    class NoInternetConnectionException: Exception("VP sharing failed due to no internet connection")

    class NetworkRequestFailed(error: String) : Exception("VP sharing failed due to this error - $error")
}