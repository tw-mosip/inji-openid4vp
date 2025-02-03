package io.mosip.openID4VP.authorizationRequest.proofJwt.exception

sealed class JWTVerificationException {
    class InvalidJWT : Exception("Invalid JWT format")

    class PublicKeyExtractionFailed(error: String) : Exception(error)

    class KidExtractionFailed(error: String) : Exception(error)

    class InvalidSignature(error: String) : Exception(error)
}
