package io.mosip.openID4VP.authorizationResponse.exception

sealed class AuthorizationResponseExceptions {
	class JsonEncodingException(fieldName: String): Exception("Error occurred while serializing the data - $fieldName")
}