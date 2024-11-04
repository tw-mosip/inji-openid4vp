package io.mosip.openID4VP.authenticationResponse

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.ClientMetadataSerializer
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.dto.Verifier

class AuthenticationResponse {
    companion object {
        fun validateAuthorizationRequestPartially(
            authorizationRequest: AuthorizationRequest,
            trustedVerifiers: List<Verifier>,
            updateAuthorizationRequest: (PresentationDefinition, ClientMetadata?) -> Unit,
        ) {
            validateVerifier(
                authorizationRequest.clientId,
                authorizationRequest.responseUri,
                trustedVerifiers
            )?.let {
                try {
                    var clientMetadata: ClientMetadata? = null
                    authorizationRequest.clientMetadata?.let {
                        clientMetadata =
                            deserializeAndValidate(
                                (authorizationRequest.clientMetadata).toString(),
                                ClientMetadataSerializer
                            )
                    }
                    val presentationDefinition: PresentationDefinition =
                        deserializeAndValidate(
                            (authorizationRequest.presentationDefinition).toString(),
                            PresentationDefinitionSerializer
                        )
                    updateAuthorizationRequest(presentationDefinition, clientMetadata)
                } catch (e: Exception) {
                    throw e
                }
            } ?: run { throw AuthorizationRequestExceptions.InvalidVerifierClientID() }
        }

        private fun validateVerifier(
            receivedClientId: String,
            receivedResponseUri: String,
            trustedVerifiers: List<Verifier>
        ): Verifier? {
            return trustedVerifiers.find { it.clientId == receivedClientId && receivedResponseUri in it.responseUris }
        }
    }
}