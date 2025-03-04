package io.mosip.openID4VP.authorizationResponse.exception


sealed class AuthorizationResponseExceptions {
    class UnsupportedCredentialFormat(message: String) : Exception(message)

    class UnsupportedResponseType(message: String) : Exception(message)

    class UnsupportedResponseMode(message: String) : Exception(message)

    class AccessDenied(message: String) : Exception(message)
}