package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.dto.VPResponseMetadata.types.LdpVPResponseMetadata
import kotlinx.serialization.Serializable
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

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
        fun constructProof(
            ldpVpResponseMetadata: LdpVPResponseMetadata,
            challenge: String,
        ): Proof {

            val formatter = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
            val createdDateAndTime = formatter.format(Date())

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