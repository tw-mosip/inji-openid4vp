package io.mosip.openID4VP.jwt.exception

sealed class JWEException {

    class UnsupportedKeyExchangeAlgorithm :
        Exception("Required Key exchange algorithm is not supported")

    class UnsupportedEncryptionAlgorithm :
        Exception("Required Encryption algorithm is not supported")
}