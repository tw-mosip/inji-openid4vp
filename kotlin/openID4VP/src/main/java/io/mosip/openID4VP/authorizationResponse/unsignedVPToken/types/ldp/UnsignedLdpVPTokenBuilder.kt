package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPTokenBuilder
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.convertJsonToMap

private val className = UnsignedLdpVPToken::class.simpleName!!

class UnsignedLdpVPTokenBuilder(
    private val verifiableCredential: List<Any>,
    private val id: String,
    private val holder: String,
): UnsignedVPTokenBuilder
{
    override fun build(): UnsignedVPToken {
        if(verifiableCredential.isEmpty()){
            throw Logger.handleException(
                exceptionType = "InvalidData",
                message = "Ldp Verifiable Credential List is empty",
                className = className
            )
        }

        val context = verifiableCredential.map { vc ->
            vc as Map<*, *>
            val contextArray = vc["@context"] as List<*>
            (contextArray[0]).toString()
        }.toSet()

        return UnsignedLdpVPToken(
            context = context.toList(),
            type = listOf("VerifiablePresentation"),
            verifiableCredential = verifiableCredential,
            id = id,
            holder = holder
        )
    }
}