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
    var jws: String = "",
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

    override fun toString(): String {
        return "Proof(challenge='$challenge', type='$type', created='$created', domain='$domain', jws='$jws', proofPurpose='$proofPurpose', verificationMethod='$verificationMethod')"
    }
}