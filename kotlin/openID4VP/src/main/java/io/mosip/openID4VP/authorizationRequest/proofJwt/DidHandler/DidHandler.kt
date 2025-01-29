import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper

import io.mosip.openID4VP.authorizationRequest.proofJwt.HandlerFactory.JwtProofTypeHandler
import io.mosip.openID4VP.common.Decoder
import io.mosip.openID4VP.exception.JWTVerificationException
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import java.nio.charset.StandardCharsets

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.util.encoders.Base64

class DidHandler : JwtProofTypeHandler {
    companion object {
        private val className = DidHandler::class.simpleName ?: "DidHandler"
        private const val RESOLVER_API = "https://resolver.identity.foundation/1.0/identifiers/"
    }

    //TODO: clientId domain name may not be specific to DidHandler, should it be named as didUrl
    override fun verify(jwtToken: String, clientId: String) {
        val url = "${RESOLVER_API}${clientId}"
        val didResponse = sendHTTPRequest(url, HTTP_METHOD.GET)
        val kid = extractKid(jwtToken)
            ?: throw JWTVerificationException.KidExtractionFailed("KidExtractionFailed: KID extraction from DID document failed (className=$className)")

        val publicKey = extractPublicKeyMultibase(kid, didResponse)
            ?: throw JWTVerificationException.PublicKeyExtractionFailed("PublicKeyExtractionFailed: Public key extraction failed (className=$className)")

        verifyJWT(jwtToken, publicKey)
    }

    private fun extractKid(jwtToken: String): String? {
        val parts = jwtToken.split(".")
        if (parts.size < 2) return null

        val headerPart = parts[0]
        val decodedHeader = Decoder.decodeBase64ToString(headerPart)
        val jsonis = convertJsonToMap(decodedHeader)
        return jsonis["kid"] as String?
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
        val parts = jwt.split(".")
        if (parts.size != 3) {
            throw JWTVerificationException.InvalidJWT()
        }
        val header = parts[0]
        val payload = parts[1]
        val signature = Base64.decode(
            parts[2].replace("-", "+").replace("_", "/")
                .padEnd((parts[2].length + 3) / 4 * 4, '=')
        )

        val publicKeyBytes = Base64.decode(publicKey)
        val publicKeyParams = Ed25519PublicKeyParameters(publicKeyBytes, 0)

        val signer = Ed25519Signer()
        signer.init(false, publicKeyParams)

        val messageBytes = "$header.$payload".toByteArray(StandardCharsets.UTF_8)
        signer.update(messageBytes, 0, messageBytes.size)

        val verificationResult: Boolean = signer.verifySignature(signature)
        if (!verificationResult)
            throw JWTVerificationException.InvalidSignature("JWT signature verification failed (className=$className)")

    }
}