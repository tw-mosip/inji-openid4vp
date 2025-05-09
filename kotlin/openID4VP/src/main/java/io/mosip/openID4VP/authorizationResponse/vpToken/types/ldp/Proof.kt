package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp

import io.mosip.openID4VP.common.DateUtil.formattedCurrentDateTime
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.LdpVPTokenSigningResult
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
            ldpVPTokenSigningResult: LdpVPTokenSigningResult,
            challenge: String,
        ): Proof {

            val createdDateAndTime = formattedCurrentDateTime()

            return Proof(
                type = ldpVPTokenSigningResult.signatureAlgorithm,
                created = createdDateAndTime,
                challenge = challenge,
                domain = ldpVPTokenSigningResult.domain,
                jws = ldpVPTokenSigningResult.jws,
                verificationMethod = ldpVPTokenSigningResult.publicKey
            )
        }
    }
}