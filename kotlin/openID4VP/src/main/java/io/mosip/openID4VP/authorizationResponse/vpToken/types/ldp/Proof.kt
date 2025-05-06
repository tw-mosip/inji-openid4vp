package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp

import io.mosip.openID4VP.common.DateUtil.formattedCurrentDateTime
import io.mosip.openID4VP.authorizationResponse.authenticationContainer.types.ldp.LdpAuthenticationContainer
import kotlinx.serialization.Serializable

@Serializable
class Proof(
    val type: String,
    val created: String,
    val challenge: String,
    val domain: String,
    val jws: String,
    val proofPurpose: String = "authentication",
    val verificationMethod: String
) {
    companion object {
        fun construct(
            ldpAuthenticationContainer: LdpAuthenticationContainer,
            challenge: String,
        ): Proof {

            val createdDateAndTime = formattedCurrentDateTime()

            return Proof(
                type = ldpAuthenticationContainer.signatureAlgorithm,
                created = createdDateAndTime,
                challenge = challenge,
                domain = ldpAuthenticationContainer.domain,
                jws = ldpAuthenticationContainer.jws,
                verificationMethod = ldpAuthenticationContainer.publicKey
            )
        }
    }
}