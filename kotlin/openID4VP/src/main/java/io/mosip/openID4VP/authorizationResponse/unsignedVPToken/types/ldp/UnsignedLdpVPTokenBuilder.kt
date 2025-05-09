package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.UnsignedVPTokenBuilder
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.convertJsonToMap

private val className = UnsignedLdpVPToken::class.simpleName!!

class UnsignedLdpVPTokenBuilder(
    private val verifiableCredential: List<String>,
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

        return UnsignedLdpVPToken(
            context = listOf("https://www.w3.org/2018/credentials/v1"),
            type = listOf("VerifiablePresentation"),
            verifiableCredential = verifiableCredential,
            id = id,
            holder = holder
        )
    }
}