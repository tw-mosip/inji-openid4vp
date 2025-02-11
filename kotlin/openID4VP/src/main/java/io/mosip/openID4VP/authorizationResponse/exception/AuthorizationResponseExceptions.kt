package io.mosip.openID4VP.authorizationResponse.exception


sealed class AuthorizationResponseExceptions {
    class UnsupportedFormatOfLibrary(message: String) : Exception(message)

    class UnsupportedResponseType(message: String) : Exception(message)

    class UnsupportedResponseMode(message: String) : Exception(message)
}