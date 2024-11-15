package io.mosip.openID4VP.networkManager

import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.io.InterruptedIOException

private val logTag = Logger.getLogTag(NetworkManagerClient::class.simpleName!!)

class NetworkManagerClient {
	companion object {
		fun sendHttpPostRequest(
			baseUrl: String, bodyParams: Map<String, String>
		): String {
			try {
				val requestBodyBuilder = FormBody.Builder()
				bodyParams.forEach { (key, value) ->
					requestBodyBuilder.add(key, value)
				}
				val requestBody = requestBodyBuilder.build()
				val client = OkHttpClient.Builder().build()
				val request = Request.Builder().url(baseUrl).post(requestBody)
					.header("Content-Type", "application/x-www-form-urlencoded").build()
				val response: Response = client.newCall(request).execute()

				if (response.code == 200) {
					return response.message
				} else {
					throw NetworkManagerClientExceptions.NetworkRequestFailed(response.toString())
				}
			} catch (exception: InterruptedIOException) {
				val specificException =
					NetworkManagerClientExceptions.NetworkRequestTimeout()
				Logger.error(logTag, specificException)
				throw specificException
			} catch (exception: Exception) {
				Logger.error(logTag, exception)
				throw exception
			}
		}

		fun sendHttpGetRequest(
			baseUrl: String
		): String {
			try {
				val client = OkHttpClient.Builder().build()
				val request =
					Request.Builder().url(baseUrl).get().build()
				val response: Response = client.newCall(request).execute()
				if (response.isSuccessful) {
					return response.body?.byteStream()?.bufferedReader().use { it?.readText() }
						?: ""
				} else {
					throw NetworkManagerClientExceptions.NetworkRequestFailed(response.toString())
				}
			} catch (exception: InterruptedIOException) {
				val specificException =
					NetworkManagerClientExceptions.NetworkRequestTimeout()
				Logger.error(logTag, specificException)
				throw specificException
			} catch (exception: Exception) {
				Logger.error(logTag, exception)
				throw exception
			}
		}
	}
}