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
import java.util.concurrent.TimeUnit

class NetworkManagerClient {
    companion object {
        private val logTag = Logger.getLogTag(this::class.simpleName!!)

        fun sendHttpPostRequest(
            baseUrl: String, queryParams: Map<String, String>, timeout: Number
        ): String {
            try {
                val urlBuilder: HttpUrl.Builder = baseUrl.toHttpUrlOrNull()!!.newBuilder()
                queryParams.forEach { (key, value) ->
                    urlBuilder.addQueryParameter(key, value)
                }
                val url = urlBuilder.build().toString()
                val client = OkHttpClient.Builder().callTimeout(1000, TimeUnit.MILLISECONDS).build()
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