package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc

import co.nstant.`in`.cbor.model.DataItem
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.UnsignedVPTokenBuilder
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.cborArrayOf
import io.mosip.openID4VP.common.cborMapOf
import io.mosip.openID4VP.common.createHashedDataItem
import io.mosip.openID4VP.common.encodeCbor
import io.mosip.openID4VP.common.getMdocDocType
import io.mosip.openID4VP.common.tagEncodedCbor
import io.mosip.openID4VP.common.toHex

private val classname = UnsignedMdocVPToken::class.simpleName!!
class UnsignedMdocVPTokenBuilder(
    private val mdocCredentials: List<String>,
    private val clientId: String,
    private val responseUri: String,
    private val verifierNonce: String,
    private val mdocGeneratedNonce: String
): UnsignedVPTokenBuilder {
    override fun build(): UnsignedVPToken {
        val unsignedDeviceAuth = mutableMapOf<String, String>()

        val clientIdHash = createHashedDataItem(clientId, mdocGeneratedNonce)
        val responseUriHash = createHashedDataItem(responseUri, mdocGeneratedNonce)

        val openId4VPHandover: DataItem =
            cborArrayOf(clientIdHash, responseUriHash, verifierNonce)

        val sessionTranscript: DataItem = cborArrayOf(null, null, openId4VPHandover)

        val deviceNamespaces: DataItem = cborMapOf()
        val deviceNameSpacesBytes = tagEncodedCbor(deviceNamespaces)

        mdocCredentials.map { mdocCredential ->
            val docType = getMdocDocType(mdocCredential)
            val deviceAuthentication: DataItem = cborArrayOf(
                "DeviceAuthentication",
                sessionTranscript,
                docType,
                deviceNameSpacesBytes
            )
            val deviceAuthenticationBytes = tagEncodedCbor(deviceAuthentication)
            if (unsignedDeviceAuth.containsKey(docType)) {
                throw Logger.handleException(
                    exceptionType = "InvalidData",
                    message = "Duplicate Mdoc Credentials with same doctype found",
                    className = classname
                )
            }
            unsignedDeviceAuth[docType] = encodeCbor(deviceAuthenticationBytes).toHex()

        }
        return UnsignedMdocVPToken(
            unsignedDeviceAuth = unsignedDeviceAuth
        )
    }
}