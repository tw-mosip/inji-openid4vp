package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.VPResponseMetadata
import io.mosip.openID4VP.constants.FormatType

/**
 * This class is for handling backward compatibility.
 * The previous version of the OpenID4VP library supported only Ldp VC and had a simplier structure.
 * This class takes the input converts in the new input format and calls the same funcions
 */
private val className = AuthorizationResponseHandlerV1::class.java.simpleName

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
            responseUri = responseUri,
            holderId = "",
            signatureSuite = "Ed25519Signature2020"
        )
        /** Even though we are returning stringified unsigned VP token, the type of the returned value is changing
         * Previous data: Stringified version of this data class:
         *
         * data class VPTokenForSigning(
         *     @SerialName("@context") val context: List<String> = listOf("https://www.w3.org/2018/credentials/v1"),
         *     val type: List<String> = listOf("VerifiablePresentation"),
         *     val verifiableCredential: List<String>,
         *     val id: String,
         *     val holder: String
         * )
         *
         * New Data: Stringified version of this data class:
         * data class UnsignedLdpVPToken(
         *     val dataToSign: String
         * )
        */


         val vpToken = unsignedVPToken[FormatType.LDP_VC] as UnsignedLdpVPToken

        println("V1 Auth Handler data to sign: ${ vpToken.dataToSign }")

        return vpToken.dataToSign

       // return Json.encodeToString(unsignedVPToken[FormatType.LDP_VC])
    }

    fun shareVP(
        vpResponseMetadata: VPResponseMetadata,
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
    ): String {
        println("$className vpResponseMetadata: $vpResponseMetadata")

        return this.authorizationResponseHandler.shareVP(
            vpResponseMetadata = vpResponseMetadata,
            nonce = authorizationRequest.nonce,
            state = authorizationRequest.state,
            responseUri = responseUri,
            presentationDefinitionId = authorizationRequest.presentationDefinition.id
        )
    }




}
