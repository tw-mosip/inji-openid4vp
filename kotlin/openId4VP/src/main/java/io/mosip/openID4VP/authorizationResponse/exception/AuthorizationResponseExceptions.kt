package io.mosip.openID4VP.authorizationResponse.exception

import androidx.core.app.NotificationCompat.MessagingStyle.Message

sealed class AuthorizationResponseExceptions {
	class JsonEncodingException(message: String): Exception("Error occurred while serializing the data - $message")
}