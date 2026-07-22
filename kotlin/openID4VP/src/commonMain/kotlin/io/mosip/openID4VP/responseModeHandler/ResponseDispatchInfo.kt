package io.mosip.openID4VP.responseModeHandler

import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk

/**
 * Data class that holds information required for dispatching responses to the verifier.
 * This includes encryption specifications, identifiers, and metadata needed by response mode handlers
 * to properly format and send authorization responses (both success and error) according to
 * OpenID4VP specifications.
 *
 * @property responseMode The response mode specified in the authorization request (e.g., "direct_post.jwt")
 * @property nonce Optional nonce value from the authorization request for replay attack prevention
 * @property state Optional state value from the authorization request to maintain request/response correlation
 * @property clientId The client identifier of the verifier/relying party
 * @property responseEncryptionSpecification Optional specification for encrypting the response
 */
data class ResponseDispatchInfo(
    val responseMode: String,
    val nonce: String?,
    val state: String?,
    val clientId: String,
    val responseEncryptionSpecification: ResponseEncryptionSpecification?
)

/**
 * Specification for encrypting authorization responses.
 *
 * @property keyEncryptionAlg The algorithm used for key encryption (e.g., "ECDH-ES")
 * @property contentEncryptionAlg The algorithm used for content encryption (e.g., "A256GCM")
 * @property verifierPublicKey The verifier's public key (JWK) used for encryption
 */
data class ResponseEncryptionSpecification(
    val keyEncryptionAlg: String,
    val contentEncryptionAlg: String,
    val verifierPublicKey: Jwk
)
