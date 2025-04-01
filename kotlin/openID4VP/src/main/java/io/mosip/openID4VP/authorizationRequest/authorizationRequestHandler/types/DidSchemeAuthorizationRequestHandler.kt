package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.WalletMetadata
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdSchemeBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.validateAuthorizationRequestObjectAndParameters
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.isJWS
import io.mosip.openID4VP.constants.ContentType.APPLICATION_FORM_URL_ENCODED
import io.mosip.openID4VP.jwt.jws.JWSHandler
import io.mosip.openID4VP.jwt.jws.JWSHandler.JwsPart.HEADER
import io.mosip.openID4VP.jwt.jws.JWSHandler.JwsPart.PAYLOAD
import io.mosip.openID4VP.jwt.keyResolver.types.DidPublicKeyResolver
import io.mosip.openID4VP.constants.ContentType.APPLICATION_JWT
import okhttp3.Headers

private val className = DidSchemeAuthorizationRequestHandler::class.simpleName!!

class DidSchemeAuthorizationRequestHandler(
    authorizationRequestParameters: MutableMap<String, Any>,
    walletMetadata: WalletMetadata?,
    setResponseUri: (String) -> Unit
) : ClientIdSchemeBasedAuthorizationRequestHandler(authorizationRequestParameters, walletMetadata, setResponseUri) {

    override fun validateRequestUriResponse(
        requestUriResponse: Map<String, Any>
    ) {
        if(requestUriResponse.isNotEmpty()){
            val headers = requestUriResponse["header"] as Headers
            val responseBody = requestUriResponse["body"].toString()

            if(isValidContentType(headers) &&  isJWS(responseBody)){
                val didUrl = getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!
                val jwsHandler = JWSHandler(responseBody, DidPublicKeyResolver(didUrl))

                val header = jwsHandler.extractDataJsonFromJws(HEADER)
                validateAuthorizationRequestSigningAlgorithm(header)

                jwsHandler.verify()

                val authorizationRequestObject = jwsHandler.extractDataJsonFromJws(PAYLOAD)

                validateAuthorizationRequestObjectAndParameters(
                    authorizationRequestParameters,
                    authorizationRequestObject
                )
                authorizationRequestParameters = authorizationRequestObject

            } else
                throw Logger.handleException(
                    exceptionType = "InvalidData",
                    className = className,
                    message = "Authorization Request must be signed for given client_id_scheme"
                )

        } else  throw Logger.handleException(
            exceptionType = "MissingInput",
            className = className,
            fieldPath = listOf(REQUEST_URI.value),
        )
    }

    override fun process(walletMetadata: WalletMetadata): WalletMetadata {
        return walletMetadata
    }

    override fun getHeadersForAuthorizationRequestUri(): Map<String, String> {
        return mapOf(
            "content-type" to APPLICATION_FORM_URL_ENCODED.value,
            "accept" to APPLICATION_JWT.value
        )
    }

    private fun isValidContentType(headers: Headers): Boolean =
        headers["content-type"]?.contains(APPLICATION_JWT.value, ignoreCase = true) == true

    private fun validateAuthorizationRequestSigningAlgorithm(headers: MutableMap<String, Any>) {
        if (shouldValidateWithWalletMetadata) {
            val alg = headers["alg"]
            walletMetadata?.let {
                if (!it.requestObjectSigningAlgValuesSupported!!.contains(alg))
                    throw Logger.handleException(
                        exceptionType = "InvalidData",
                        className = className,
                        message = "request_object_signing_alg is not support by wallet"
                    )
            }
        }
    }
}

