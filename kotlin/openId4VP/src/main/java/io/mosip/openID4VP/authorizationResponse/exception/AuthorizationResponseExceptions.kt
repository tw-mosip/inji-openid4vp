package io.mosip.openID4VP.authorizationResponse.exception

import androidx.core.app.NotificationCompat.MessagingStyle.Message

sealed class AuthorizationResponseExceptions {
	class JsonEncodingException(fieldName: String): Exception("Error occurred while serializing the data - $fieldName")
}