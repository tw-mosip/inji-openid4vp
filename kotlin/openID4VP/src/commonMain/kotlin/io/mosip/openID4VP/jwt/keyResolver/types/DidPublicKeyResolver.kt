package io.mosip.openID4VP.jwt.keyResolver.types

import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.jwt.keyResolver.PublicKeyResolver
import io.mosip.vercred.vcverifier.DidWebResolver

private val className = DidPublicKeyResolver::class.simpleName!!

class DidPublicKeyResolver(private val didUrl: String) : PublicKeyResolver {

    //TODO: should create public key object from the string based on signature algorithm
    override fun resolveKey(header: Map<String, Any>): String {
        val didResponse = try {
            DidWebResolver(didUrl).resolve()
        }catch (e: Exception){
            throw OpenID4VPExceptions.PublicKeyResolutionFailed(e.message.toString(), className)
        }

        val kid = header["kid"]?.toString()
            ?: throw OpenID4VPExceptions.KidExtractionFailed("KID extraction from DID document failed",
                className)

        return extractPublicKeyMultibase(kid, didResponse)
            ?: throw  OpenID4VPExceptions.PublicKeyExtractionFailed("Public key extraction failed", className)
    }

    private fun extractPublicKeyMultibase(kid: String, didDocument: Map<String, Any>): String? {
        val verificationMethods = didDocument["verificationMethod"] as? List<Map<String, Any>> ?: return null

        for (method in verificationMethods) {
            if (method["id"] == kid) {
                val publicKeyMultibase = method["publicKeyMultibase"] as? String
                if (!publicKeyMultibase.isNullOrEmpty()) return publicKeyMultibase

                if (PUBLIC_KEY_TYPES.any { method.containsKey(it) }) {
                    throw OpenID4VPExceptions.UnsupportedPublicKeyType(
                        className
                    )
                }
            }
        }
        return null
    }

    companion object{
        val PUBLIC_KEY_TYPES = listOf("publicKey", "publicKeyJwk", "publicKeyPem", "publicKeyHex")
    }


}