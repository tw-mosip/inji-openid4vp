package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp

import io.mosip.openID4VP.common.DateUtil.formattedCurrentDateTime
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.VPResponseMetadata
import kotlinx.serialization.Serializable

@Serializable
class Proof(
    val type: String,
    val created: String,
    val challenge: String,
    val domain: String,
    var proofValue: String? = null,
    var jws: String? = null,
    val proofPurpose: String = "authentication",
    var verificationMethod: String
) {

    companion object {
        @Deprecated("Use VPResponseMetadata to construct Proof")
        fun constructProof(
            vpResponseMetadata: VPResponseMetadata,
            challenge: String,
        ): Proof {
            val createdDateAndTime = formattedCurrentDateTime()
            return Proof(
                type = vpResponseMetadata.signatureAlgorithm,
                created = createdDateAndTime,
                challenge = challenge,
                domain = vpResponseMetadata.domain,
                proofValue = vpResponseMetadata.jws,
                verificationMethod = vpResponseMetadata.publicKey
            )
        }
    }

}