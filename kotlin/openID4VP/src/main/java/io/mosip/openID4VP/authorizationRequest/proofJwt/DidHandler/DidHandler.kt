import io.mosip.openID4VP.authorizationRequest.proofJwt.DidHandler.DidUtils
import io.mosip.openID4VP.authorizationRequest.proofJwt.HandlerFactory.JwtProofTypeHandler
import io.mosip.openID4VP.exception.JWTVerificationException
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.util.encoders.Base64
import java.nio.charset.StandardCharsets

class DidHandler : JwtProofTypeHandler {
    companion object {
        private val className = DidHandler::class.simpleName ?: "DidHandler"
        private const val RESOLVER_API = "https://resolver.identity.foundation/1.0/identifiers/"
    }

    //TODO: clientId domain name may not be specific to DidHandler, should it be named as didUrl
    override fun verify(jwtToken: String, clientId: String) {
        val url = "${RESOLVER_API}${clientId}"
        val didResponse = sendHTTPRequest(url, HTTP_METHOD.GET)
        val kid = DidUtils.extractKid(jwtToken)
            ?: throw JWTVerificationException.KidExtractionFailed("KidExtractionFailed: KID extraction from DID document failed (className=$className)")

        val publicKey = DidUtils.extractPublicKeyMultibase(kid, didResponse)
            ?: throw JWTVerificationException.PublicKeyExtractionFailed("PublicKeyExtractionFailed: Public key extraction failed (className=$className)")

        verifyJWT(jwtToken, publicKey)
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