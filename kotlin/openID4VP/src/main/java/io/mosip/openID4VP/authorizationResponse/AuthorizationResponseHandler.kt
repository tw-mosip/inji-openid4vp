package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning.CredentialFormatSpecificSigningData
import io.mosip.openID4VP.common.FormatType

class AuthorizationResponseHandler {
    private var vpTokensForSigning: MutableMap<FormatType, CredentialFormatSpecificSigningData> = mutableMapOf()

    @Throws(Exception::class)
    fun constructDataForSigning(credentialsMap: Map<String, Map<String, List<Any>>>): MutableMap<FormatType, CredentialFormatSpecificSigningData> {
        vpTokensForSigning = CredentialFormatSpecificSigningDataMapCreator().create(selectedCredentials = credentialsMap)
        return vpTokensForSigning
    }
}