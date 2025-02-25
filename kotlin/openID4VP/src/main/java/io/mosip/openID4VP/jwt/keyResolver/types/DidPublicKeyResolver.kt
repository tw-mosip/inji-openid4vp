package io.mosip.openID4VP.jwt.keyResolver.types

import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.jwt.keyResolver.PublicKeyResolver
import io.mosip.vercred.vcverifier.DidWebResolver

private val className = DidPublicKeyResolver::class.simpleName!!

class DidPublicKeyResolver(private val didUrl: String) : PublicKeyResolver {

    //TODO: should create public key object from the string based on signature algorithm
    override fun resolveKey(header: Map<String, Any>): String {
        val didResponse = try {
            DidWebResolver(didUrl).resolve()
        }catch (e: Exception){
            throw Logger.handleException(
                exceptionType = "PublicKeyResolutionFailed",
                className = className,
                message = e.message
            )
        }

        val kid = header["kid"]?.toString()
            ?: throw Logger.handleException(
                exceptionType = "KidExtractionFailed",
                className = className,
                message = "KID extraction from DID document failed"
            )
        return extractPublicKeyMultibase(kid, didResponse)
            ?: throw Logger.handleException(
                exceptionType = "PublicKeyExtractionFailed",
                className = className,
                message = "Public key extraction failed"
            )
    }

    private fun extractPublicKeyMultibase(kid: String, didDocument: Map<String, Any>): String? {
        val verificationMethod = didDocument["verificationMethod"] as? List<Map<String, Any>>
        if (verificationMethod != null) {
            for (method in verificationMethod) {
                val id = method["id"] as? String
                val publicKeyMultibase = method["publicKey"] as? String
                if (id == kid && !publicKeyMultibase.isNullOrEmpty()) {
                    return publicKeyMultibase
                }
            }
        }
        return null
    }
}