

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.JOSEException

import io.mosip.openID4VP.authorizationRequest.proofJwt.HandlerFactory.JwtProofTypeHandler
import io.mosip.openID4VP.common.Decoder
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import java.text.ParseException
import java.nio.charset.StandardCharsets

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.util.encoders.Base64

import java.security.*

class DidHandler : JwtProofTypeHandler {
    companion object {
        private val className = DidHandler::class.simpleName ?: "DidHandler"
    }

    override fun verify(jwtToken: String, clientId: String) {

        val RESOLVER_API = "https://resolver.identity.foundation/1.0/identifiers/"
        val url = "${RESOLVER_API}${clientId}"
        val response = sendHTTPRequest(url,HTTP_METHOD.GET)

        val kid = extractKid(jwtToken)
            ?: throw Exception("KidExtractionFailed: KID extraction from DID document failed (className=$className)")

        val publicKey = extractPublicKeyMultibase(kid, response)
            ?: throw Exception("PublicKeyExtractionFailed: Public key extraction failed (className=$className)")

        verifyJWT(jwtToken, publicKey)
    }

    private fun extractKid(jwtToken: String): String? {
        val parts = jwtToken.split(".")
        if (parts.size < 2) return null

        val headerPart = parts[0]
        val decodedHeader = Decoder.decodeBase64ToString(headerPart)
        val jsonis = convertJsonToMap(decodedHeader)
        return jsonis["kid"] as String
    }

    fun convertJsonToMap(jsonString: String): Map<String, Any> {
        val mapper = jacksonObjectMapper()
        return mapper.readValue(jsonString, object : TypeReference<Map<String, Any>>() {})
    }

    private fun extractPublicKeyMultibase(kid: String, response: String): String? {
        val rootJson = convertJsonToMap(response)
        val didDocument = rootJson["didDocument"] as Map<*, *>
        val verificationMethod = didDocument["verificationMethod"] as? List<Map<String, Any>>

        if (verificationMethod != null) {
            for (method in verificationMethod) {
                val id = method["id"] as? String
                val publicKeyMultibase = method["publicKeyMultibase"] as? String
                if (id == kid && !publicKeyMultibase.isNullOrEmpty()) {
                    return publicKeyMultibase
                }
            }
        }
        return null
    }

    private fun verifyJWT(jwt: String, publicKey: String) {
        try {

            val jwt = "eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6d2ViOmFkaXR5YW5rYW5uYW4tdHcuZ2l0aHViLmlvOm9wZW5pZDR2cDpmaWxlcyNrZXktMCJ9.eyJwcmVzZW50YXRpb25fZGVmaW5pdGlvbiI6IntcImlkXCI6XCJ2cCB0b2tlbiBleGFtcGxlXCIsXCJwdXJwb3NlXCI6XCJSZWx5aW5nIHBhcnR5IGlzIHJlcXVlc3RpbmcgeW91ciBkaWdpdGFsIElEIGZvciB0aGUgcHVycG9zZSBvZiBTZWxmLUF1dGhlbnRpY2F0aW9uXCIsXCJmb3JtYXRcIjp7XCJsZHBfdmNcIjp7XCJwcm9vZl90eXBlXCI6W1wiUnNhU2lnbmF0dXJlMjAxOFwiXX19LFwiaW5wdXRfZGVzY3JpcHRvcnNcIjpbe1wiaWRcIjpcImlkIGNhcmQgY3JlZGVudGlhbFwiLFwiZm9ybWF0XCI6e1wibGRwX3ZjXCI6e1wicHJvb2ZfdHlwZVwiOltcIkVkMjU1MTlTaWduYXR1cmUyMDIwXCJdfX0sXCJjb25zdHJhaW50c1wiOntcImZpZWxkc1wiOlt7XCJwYXRoXCI6W1wiJC5jcmVkZW50aWFsU3ViamVjdC5lbWFpbFwiXSxcImZpbHRlclwiOntcInR5cGVcIjpcInN0cmluZ1wiLFwicGF0dGVyblwiOlwiQGdtYWlsLmNvbVwifX1dfX1dfSIsImNsaWVudF9tZXRhZGF0YSI6IntcImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZ1wiOlwiRUNESC1FU1wiLFwiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jXCI6XCJBMjU2R0NNXCIsXCJ2cF9mb3JtYXRzXCI6e1wibXNvX21kb2NcIjp7XCJhbGdcIjpbXCJFUzI1NlwiLFwiRWREU0FcIl19LFwibGRwX3ZwXCI6e1wicHJvb2ZfdHlwZVwiOltcIkVkMjU1MTlTaWduYXR1cmUyMDE4XCIsXCJFZDI1NTE5U2lnbmF0dXJlMjAyMFwiLFwiUnNhU2lnbmF0dXJlMjAxOFwiXX19LFwicmVxdWlyZV9zaWduZWRfcmVxdWVzdF9vYmplY3RcIjp0cnVlfSIsInN0YXRlIjoiU2EycUdXZTY4VmJidGx2ZUxxbjFzZz09Iiwibm9uY2UiOiIvTEUzS0ZpaFhsM3hUNjhLeWJob3NBPT0iLCJjbGllbnRfaWQiOiJkaWQ6d2ViOmFkaXR5YW5rYW5uYW4tdHcuZ2l0aHViLmlvOm9wZW5pZDR2cDpmaWxlcyIsImNsaWVudF9pZF9zY2hlbWUiOiJkaWQiLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJyZXNwb25zZV91cmkiOiJodHRwczovLzQ2YjItNDUtMTEyLTY4LTE5MC5uZ3Jvay1mcmVlLmFwcC92ZXJpZmllci92cC1yZXNwb25zZSJ9.jIDQsTGaN-5J5tZiRbYbC7-8UFnL-UY3qCamc6DYX_nAzQ4cSJovsEbt2DgQzADECc2042xJ7iAbqfydv48DAA"

            val parts = jwt.split(".")
            if (parts.size != 3) {
                throw IllegalArgumentException("Invalid JWT format")
            }

            val header = parts[0]
            val payload = parts[1]
            val signature = Base64.decode(parts[2].replace("-", "+").replace("_", "/")
                .padEnd((parts[2].length + 3) / 4 * 4, '='))

            // Decode public key
            val publicKeyBytes = Base64.decode(publicKey)
            val publicKeyParams = Ed25519PublicKeyParameters(publicKeyBytes, 0)

            // Create signer
            val signer = Ed25519Signer()
            signer.init(false, publicKeyParams)

            // Add the message to verify (header.payload)
            val messageBytes = "$header.$payload".toByteArray(StandardCharsets.UTF_8)
            signer.update(messageBytes, 0, messageBytes.size)

            // Verify signature
            val ressss =  signer.verifySignature(signature)

            println(ressss)


//            val strReader = StringReader(publicKey)
//            val pemReader = PemReader(strReader)
//
//            val pemObject = pemReader.readPemObject()
//            val pubKeyBytes = pemObject.content
//            val pubKeySpec = X509EncodedKeySpec(pubKeyBytes)
//            val keyFactory = KeyFactory.getInstance("Ed25519")
//            val pbObj =  keyFactory.generatePublic(pubKeySpec)
//
//            val jwsObject = JWSObject.parse(jwt)
//            //val signature = jwsObject.signature.decode()
//
//            val h = jwsObject.header.toBase64URL().toString().toByteArray(StandardCharsets.UTF_8);
//            val p = jwsObject.payload.toBase64URL().toString().toByteArray(StandardCharsets.UTF_8);
//
//            val jwsSigningInput = ByteArray(h.size + 1 + p.size)
//            System.arraycopy(h, 0, jwsSigningInput, 0, h.size)
//            jwsSigningInput[h.size] = '.'.code.toByte()
//            System.arraycopy(
//                p,
//                0,
//                jwsSigningInput,
//                h.size + 1,
//                p.size
//            )
//
//
//            val res = getVerificationResult(pbObj, jwsSigningInput, signature)
//            println(res)



            /*val jwsObject = JWSObject.parse(jwt)
            val signature = jwsObject.signature.decode()

            // 1. Parse the JWT
            val signedJWT = SignedJWT.parse(jwt)

            // 2. Decode and parse the public key
            val decodedPublicKey = Decoder.decodeBase64ToString(publicKey)
           val publicKeySpec = EdDSAPublicKeySpec(decodedPublicKeyBytes)


            val verifier = Ed25519Verifier(publicKeySpec)

            // 3. Verify the signature
            if (signedJWT.verify(verifier)) {
                // 4. Parse the claims
                val claimsSet = signedJWT.jwtClaimsSet
                return claimsSet
            } else {
                println("JWT signature verification failed.")
                return null
            }*/
        } catch (e: ParseException) {
            println("Error parsing JWT: ${e.message}")

        } catch (e: JOSEException) {
            println("Error verifying JWT: ${e.message}")

        }
    }

    private fun getVerificationResult(
        pbObj: PublicKey?,
        jwsSigningInput: ByteArray,
        signature: ByteArray?
    ) : Boolean{
        Signature.getInstance("Ed25519")
            .apply {
                initVerify(pbObj)
                update(jwsSigningInput)
               return verify(signature)
            }
    }
}