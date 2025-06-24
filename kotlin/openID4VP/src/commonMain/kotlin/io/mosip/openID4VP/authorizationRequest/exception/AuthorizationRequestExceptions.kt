package io.mosip.openID4VP.authorizationRequest.exception


sealed class AuthorizationRequestExceptions {

    class InvalidVerifier(message: String) : Exception(message)

    class InvalidInputPattern(fieldPath: String) :
        Exception("Invalid Input Pattern: $fieldPath pattern is not matching with OpenId4VP specification")

    class JsonEncodingFailed(fieldPath: String, message: String) :
        Exception("Json encoding failed for $fieldPath due to this error: $message")

    class DeserializationFailure(fieldPath: String, message: String) :
        Exception("Deserializing for $fieldPath failed due to this error: $message")

    class InvalidLimitDisclosure :
        Exception("Invalid Input: constraints->limit_disclosure value should be preferred")

    class InvalidQueryParams(message: String) : Exception(message)

}



