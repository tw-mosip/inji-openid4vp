package io.mosip.openID4VP.jwt.exception

sealed class JWTVerificationException {
    class InvalidJWT(message: String) : Exception(message)

    class PublicKeyExtractionFailed(message: String) : Exception(message)

    class KidExtractionFailed(message: String) : Exception(message)

    class InvalidSignature(message: String) : Exception(message)
}
