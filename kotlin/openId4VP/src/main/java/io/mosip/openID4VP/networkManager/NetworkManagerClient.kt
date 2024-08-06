package io.mosip.openID4VP.networkManager

import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions
import okhttp3.*
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import java.io.IOException
import java.io.InterruptedIOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit

class NetworkManagerClient {
    companion object{
        fun sendHttpPostRequest(
            baseUrl: String,
            queryParams: Map<String, String>,
            timeout: Number
        ): String {
            try {
                val urlBuilder: HttpUrl.Builder = baseUrl.toHttpUrlOrNull()!!.newBuilder()
                queryParams.forEach { (key, value) ->
                    urlBuilder.addQueryParameter(key, value)
                }
                val url = urlBuilder.build().toString()
                val client =
                    OkHttpClient.Builder().callTimeout(1000, TimeUnit.MILLISECONDS)
                        .build()
                val request = Request.Builder()
                    .url(url)
                    .get()
                    .build()

                val response: Response = client.newCall(request).execute()

                if(response.code == 200){
                    return response.message
                }else{
                    throw NetworkManagerClientExceptions.NetworkRequestFailed(response.message)
                }
            }catch (exception: InterruptedIOException){
                throw NetworkManagerClientExceptions.NetworkRequestFailedDueToConnectionTimeout()
            } catch (exception: IOException) {
                when (exception) {
                    is UnknownHostException -> {
                        throw NetworkManagerClientExceptions.NetworkRequestFailed(exception.message!!)
                    }
                    else -> {
                        throw NetworkManagerClientExceptions.NetworkRequestFailed(exception.message!!)
                    }
                }
            }
        }
    }
}