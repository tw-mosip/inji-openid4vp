package io.mosip.openID4VP.authorizationRequest.exception


sealed class AuthorizationRequestExceptions {

    class InvalidVerifierClientID :
        Exception("VP sharing failed: Verifier authentication was unsuccessful")

    class DecodingException(message: String) : Exception(message)

    class MissingInput(fieldName: String) : Exception("Missing Input: $fieldName param is required")

    class InvalidInput(fieldName: String) :
        Exception("Invalid Input: $fieldName value cannot be empty or null")

    class InvalidInputPattern(fieldName: String) :
        Exception("Invalid Input Pattern: $fieldName pattern is not matching with OpenId4VP specification")

    class InvalidLimitDisclosure :
        Exception("Invalid Input: limit_disclosure value should be either required or preferred")

    class InvalidQueryParams(message: String) : Exception(message)
}