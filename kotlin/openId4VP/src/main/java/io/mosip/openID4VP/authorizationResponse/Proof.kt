package io.mosip.openID4VP.authorizationResponse

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class Proof(
    val type: String,
    val created: String,
    val challenge: String,
    val domain: String,
    val jws: String,
    val proofPurpose: String = "authentication",
    val verificationMethod: String
){
    companion object{
        fun constructProof(
            signingAlgorithm: String,
            challenge: String,
            domain: String,
            jws: String,
            publicKey: String,
        ): Proof {

            val formatter = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
            val createdDateAndTime = formatter.format(Date())

            return Proof(
                type = signingAlgorithm,
                created = createdDateAndTime,
                challenge = challenge,
                domain = domain,
                jws = jws,
                verificationMethod = publicKey
            )
        }
    }
}