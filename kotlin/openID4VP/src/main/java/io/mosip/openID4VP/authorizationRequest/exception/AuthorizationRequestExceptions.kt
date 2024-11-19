package io.mosip.openID4VP.authorizationRequest.exception


sealed class AuthorizationRequestExceptions {

    class InvalidVerifierClientID :
        Exception("VP sharing failed: Verifier authentication was unsuccessful")

    class DecodingException(message: String) : Exception(message)

    class MissingInput(fieldPath: String) : Exception("Missing Input: $fieldPath param is required")

    class InvalidInput(fieldPath: String) :
        Exception("Invalid Input: $fieldPath value cannot be empty or null")

    class InvalidInputPattern(fieldPath: String) :
        Exception("Invalid Input Pattern: $fieldPath pattern is not matching with OpenId4VP specification")

    class JsonEncodingFailed(fieldPath: String, message: String) :
        Exception("Json encoding failed for $fieldPath due to this error: $message")

    class InvalidLimitDisclosure :
        Exception("Invalid Input: constraints->limit_disclosure value should be either required or preferred")

    class InvalidQueryParams(message: String) : Exception(message)
}