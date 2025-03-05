package io.mosip.openID4VP.authorizationResponse.exception

sealed class JWEExceptions {

    class UnsupportedKeyExchangeAlgorithm :
        Exception("Required Key exchange algorithm is not supported")

    class UnsupportedEncryptionAlgorithm :
        Exception("Required Encryption algorithm is not supported")
}