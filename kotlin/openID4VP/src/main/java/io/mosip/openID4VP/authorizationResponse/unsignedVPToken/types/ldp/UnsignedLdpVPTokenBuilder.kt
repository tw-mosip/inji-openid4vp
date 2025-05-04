package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.UnsignedVPTokenBuilder

class UnsignedLdpVPTokenBuilder(
    private val verifiableCredential: List<String>,
    private val id: String,
    private val holder: String,
): UnsignedVPTokenBuilder
{
    override fun build(): UnsignedVPToken {
        return UnsignedLdpVPToken(
            context = listOf("https://www.w3.org/2018/credentials/v1"),
            type = listOf("VerifiablePresentation"),
            verifiableCredential = verifiableCredential,
            id = id,
            holder = holder
        )
    }
}