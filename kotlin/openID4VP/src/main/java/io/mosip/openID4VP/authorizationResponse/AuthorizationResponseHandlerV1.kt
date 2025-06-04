package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.LdpVPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.VPResponseMetadata
import io.mosip.openID4VP.constants.FormatType
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

internal class AuthorizationResponseHandlerV1 {
    private var authorizationResponseHandler: AuthorizationResponseHandler =
        AuthorizationResponseHandler()

    fun constructUnsignedVPToken(
        verifiableCredentials: Map<String, List<String>>,
        authorizationRequest: AuthorizationRequest,
        responseUri: String
    ): String {
        //TODO: should we convert the list of stringified credential to list of json objects?
        val transformedCredentials = verifiableCredentials.mapValues { (_, credentials) ->
            mapOf(FormatType.LDP_VC to credentials)
        }

        val unsignedVPToken = authorizationResponseHandler.constructUnsignedVPToken(
            credentialsMap = transformedCredentials,
            authorizationRequest = authorizationRequest,
            responseUri = responseUri
        )
        return Json.encodeToString(unsignedVPToken[FormatType.LDP_VC])
    }

    fun shareVP(
        vpResponseMetadata: VPResponseMetadata,
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
    ): String {

        val vpTokenSigningResult = LdpVPTokenSigningResult(
            jws = vpResponseMetadata.jws,
            signatureAlgorithm = vpResponseMetadata.signatureAlgorithm,
            publicKey = vpResponseMetadata.publicKey,
            domain = vpResponseMetadata.domain
        )
        println("VP Token Signing Result: $vpTokenSigningResult")
        val vpTokenSigningResults: Map<FormatType, VPTokenSigningResult> = mapOf(
            FormatType.LDP_VC to vpTokenSigningResult
        )

        println("VP Token Signing Results: $vpTokenSigningResults")

        return authorizationResponseHandler.shareVP(
            authorizationRequest = authorizationRequest,
            vpTokenSigningResults = vpTokenSigningResults,
            responseUri = responseUri
        )
    }
}
