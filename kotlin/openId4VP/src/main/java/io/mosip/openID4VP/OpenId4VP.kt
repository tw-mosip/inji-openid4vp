package io.mosip.openID4VP

import android.net.Uri
import io.mosip.openID4VP.models.PresentationDefinition
import io.mosip.openID4VP.models.AuthorizationRequest
import io.mosip.openID4VP.models.AuthenticationResponse
import io.mosip.openID4VP.models.Verifier
import io.mosip.openID4VP.utils.Decoder
import io.mosip.openID4VP.utils.Deserializer
class OpenId4VP {

    private lateinit var authorizationRequest: AuthorizationRequest
    private lateinit var trustedVerifiers: List<Verifier>

    fun authenticateVerifier(encodedAuthorizationRequest: String, trustedVerifiers: List<Verifier>): AuthenticationResponse?{
        this.trustedVerifiers = trustedVerifiers

        val decoder = Decoder()
        val decodedAuthorizationRequest: String = decoder.decodeBase64ToString(encodedAuthorizationRequest)

        parseAuthorizationRequest(decodedAuthorizationRequest)

        val authenticatedVerifierInfo = validateVerifierClientId(authorizationRequest.clientId)

        return authenticatedVerifierInfo?.let { AuthenticationResponse(it,authorizationRequest.presentationDefinition)}
    }

    private fun parseAuthorizationRequest(authorizationRequestQueryString: String) {
        try {
            val uri = Uri.parse("?$authorizationRequestQueryString")!!
            val clientId: String = uri.getQueryParameter("client_id")!!
            val responseType: String = uri.getQueryParameter("response_type")!!
            val responseMode: String = uri.getQueryParameter("response_mode")!!
            val presentationDefinitionJson: String = uri.getQueryParameter("presentation_definition")!!
            val responseUri: String = uri.getQueryParameter("response_uri")!!
            val nonce: String = uri.getQueryParameter("nonce")!!
            val state: String = uri.getQueryParameter("state")!!

            val deserializer = Deserializer()
            val presentationDefinition: PresentationDefinition = deserializer.deserializeJsonIntoClassInstance(presentationDefinitionJson)

            val authorizationRequest = AuthorizationRequest(
                clientId = clientId,
                responseType = responseType,
                responseMode=responseMode,
                presentationDefinition = presentationDefinition,
                responseUri=responseUri,
                nonce = nonce,
                state=state
            )

            this.authorizationRequest= authorizationRequest
        }catch (e: IllegalArgumentException){
            throw Error("Invalid authorization request parameters: ${e.message}")
        }

    }

    private fun validateVerifierClientId(receivedClientId: String?): Verifier?{
        return this.trustedVerifiers.find{it.clientId==receivedClientId}
    }

}