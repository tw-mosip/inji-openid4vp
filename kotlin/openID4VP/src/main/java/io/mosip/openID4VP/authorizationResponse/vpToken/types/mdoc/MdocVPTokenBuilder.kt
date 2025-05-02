package io.mosip.openID4VP.authorizationResponse.vpToken.types.mdoc


import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenBuilder
import io.mosip.openID4VP.common.Decoder
import io.mosip.openID4VP.common.Encoder
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.cborArrayOf
import io.mosip.openID4VP.common.cborMapOf
import io.mosip.openID4VP.common.decodeCbor
import io.mosip.openID4VP.common.encodeCbor
import io.mosip.openID4VP.common.getMdocDocType
import io.mosip.openID4VP.common.mapSigningAlgorithmToProtectedAlg
import io.mosip.openID4VP.common.tagEncodedCbor
import io.mosip.openID4VP.dto.vpResponseMetadata.types.MdocVPResponseMetadata

private val className = MdocVPTokenBuilder::class.java.simpleName

class MdocVPTokenBuilder(
    private val mdocVPResponseMetadata: MdocVPResponseMetadata,
    private val mdocCredentials: List<String>,
) : VPTokenBuilder {
    override fun build(): MdocVPToken {
        val documents = mdocCredentials.map { credential ->
            val credentialDocType = getMdocDocType(credential) //TODO: Extract the decoding logic here to be reused

            val deviceAuthSignature = mdocVPResponseMetadata.deviceAuthenticationSignature[credentialDocType]
                ?: throwMissingInput("Device authentication signature not found for mdoc credential docType $credentialDocType")

            val signature = deviceAuthSignature.signature
            val mdocAuthenticationAlgorithm = deviceAuthSignature.algorithm

            val deviceSignature = createDeviceSignature(mdocAuthenticationAlgorithm, signature)

            val deviceNamespacesBytes = tagEncodedCbor(cborMapOf())
            val deviceAuth = cborMapOf("deviceSignature" to deviceSignature)
            val deviceSigned = cborMapOf(
                "deviceAuth" to deviceAuth,
                "nameSpaces" to deviceNamespacesBytes
            )


            val document = decodeCbor(
                Decoder.decodeBase64Data(credential)
            ) as Map

            document.put(UnicodeString("deviceSigned"), deviceSigned)
            document
        }

        val response = cborMapOf(
            "version" to "1.0",
            "documents" to cborArrayOf(*documents.toTypedArray()),
            "status" to 0
        )

        return MdocVPToken(Encoder.encodeToBase64Url(encodeCbor(response)))
    }

    private fun createDeviceSignature(
        signingAlgorithm: String,
        signature: String
    ): DataItem {
        val base64DecodedSignature = Decoder.decodeBase64Data(signature)
        val cborEncodedSignature = encodeCbor(ByteString(base64DecodedSignature))

        val protectedSigningAlgorithm = mapSigningAlgorithmToProtectedAlg(signingAlgorithm)

        val protectedHeader = encodeCbor(cborMapOf(1 to protectedSigningAlgorithm))
        val unprotectedHeader = cborMapOf()

        return cborArrayOf(protectedHeader, unprotectedHeader, null, cborEncodedSignature)
    }

    private fun throwMissingInput(message: String): Nothing {
        throw Logger.handleException(
            exceptionType = "MissingInput",
            message = message,
            className = className
        )
    }
}

