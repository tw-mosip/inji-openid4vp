package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldpVp

import io.mosip.openID4VP.common.DateUtil.formattedCurrentDateTime
import io.mosip.openID4VP.dto.VPResponseMetadata.types.LdpVPResponseMetadata
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
            ldpVpResponseMetadata: LdpVPResponseMetadata,
            challenge: String,
        ): Proof {

            val createdDateAndTime = formattedCurrentDateTime()

            return Proof(
                type = ldpVpResponseMetadata.signatureAlgorithm,
                created = createdDateAndTime,
                challenge = challenge,
                domain = ldpVpResponseMetadata.domain,
                jws = ldpVpResponseMetadata.jws,
                verificationMethod = ldpVpResponseMetadata.publicKey
            )
        }
    }
}