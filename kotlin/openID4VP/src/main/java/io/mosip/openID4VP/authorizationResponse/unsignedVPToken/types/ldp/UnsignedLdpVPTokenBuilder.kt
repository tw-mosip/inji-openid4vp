package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp

import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPTokenBuilder
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.convertJsonToMap


class UnsignedLdpVPTokenBuilder(
    private val verifiableCredential: List<Any>,
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