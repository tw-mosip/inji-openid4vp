package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import foundation.identity.jsonld.JsonLDObject
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.Proof
import io.mosip.openID4VP.common.DateUtil.formattedCurrentDateTime
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json


class UnsignedLdpVPTokenBuilder(
    private val verifiableCredential: List<Any>,
    private val id: String,
    private val holder: String,
    private val challenge: String,
    private val domain: String
): UnsignedVPTokenBuilder
{
    override fun build(): Map<String, Any> {

        val unsignedLdpVPToken =  LdpVPToken(
            context = listOf("https://www.w3.org/2018/credentials/v1"),
            type = listOf("VerifiablePresentation"),
            verifiableCredential = verifiableCredential,
            id = id,
            holder = holder,
            proof = Proof(
                type = "Ed25519Signature2020",
                created = formattedCurrentDateTime(),
                proofPurpose = "assertionMethod",
                verificationMethod = holder,
                domain = domain,
                challenge = challenge
            )
        )

        val mapper = jacksonObjectMapper().apply {
            configOverride(Proof::class.java).setInclude(
                JsonInclude.Value.construct(
                    JsonInclude.Include.NON_EMPTY,
                    JsonInclude.Include.NON_EMPTY
                )
            )
        }

        val unsignedVPTokenMap = mapper.writeValueAsString(unsignedLdpVPToken)
        val vcJsonLdObject: JsonLDObject = JsonLDObject.fromJson(unsignedVPTokenMap)

        val dataToSign = vcJsonLdObject.toJson()


        val result = mapOf("unsignedLdpVPToken" to unsignedLdpVPToken, "dataToSign" to dataToSign)

        return  result
    }
}