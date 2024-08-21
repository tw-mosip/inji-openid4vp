package io.mosip.openID4VP.networkManager

import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.io.IOException
import java.io.InterruptedIOException
import java.net.UnknownHostException

private val logTag = Logger.getLogTag(NetworkManagerClient::class.simpleName!!)

class NetworkManagerClient {
	companion object {
		fun sendHttpPostRequest(
			baseUrl: String, queryParams: Map<String, String>
		): String {
			try {
				val urlBuilder: HttpUrl.Builder = baseUrl.toHttpUrlOrNull()!!.newBuilder()
				queryParams.forEach { (key, value) ->
					urlBuilder.addQueryParameter(key, value)
				}
				val url = urlBuilder.build().toString()
				println("url::" + url)
				val client = OkHttpClient.Builder().build()
				println("client::" + client)
				val request = Request.Builder().url(url).get().build()

				val response: Response = client.newCall(request).execute()

				if (response.code == 200) {
					return response.message
				} else {
					throw NetworkManagerClientExceptions.NetworkRequestFailed(response.message)
				}
			} catch (exception: InterruptedIOException) {
				val specificException =
					NetworkManagerClientExceptions.NetworkRequestFailedDueToConnectionTimeout()
				Logger.error(logTag, specificException)
				throw specificException
			} catch (exception: UnknownHostException) {
				val specificException =
					NetworkManagerClientExceptions.NetworkRequestFailed(exception.message!!)
				Logger.error(logTag, specificException)
				throw specificException
			} catch (exception: IOException) {
				val specificException =
					NetworkManagerClientExceptions.NetworkRequestFailed(exception.message!!)
				Logger.error(logTag, specificException)
				throw specificException
			}
		}
	}
}