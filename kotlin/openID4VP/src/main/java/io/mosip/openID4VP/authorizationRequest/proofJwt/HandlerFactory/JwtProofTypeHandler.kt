package io.mosip.openID4VP.authorizationRequest.proofJwt.HandlerFactory

interface JwtProofTypeHandler {
    fun verify(jwtToken: String, clientId: String)
}