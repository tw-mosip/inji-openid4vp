package io.mosip.openID4VP.networkManager

import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions
import okhttp3.*
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import java.io.IOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit


class NetworkManagerClient {
    companion object{
         fun sendHttpPostRequest(baseUrl: String, queryParams: Map<String,String>, timeout: Number): Response? {
             try {
                 val urlBuilder: HttpUrl.Builder = baseUrl.toHttpUrlOrNull()!!.newBuilder()
                 queryParams.forEach { (key, value) ->
                     urlBuilder.addQueryParameter(key, value)
                 }
                 val url = urlBuilder.build().toString()
                 val client = OkHttpClient.Builder().connectTimeout(timeout.toLong(), TimeUnit.MILLISECONDS).build()
                 val request = Request.Builder()
                     .url(url)
                     .get()
                     .build()

                 val response: Response = client.newCall(request).execute()
                 if(response.code == 200){
                     return response
                 }
                 return null
             } catch (exception: IOException) {
                 when (exception) {
                     is SocketTimeoutException -> {
                        throw NetworkManagerClientExceptions.NetworkRequestFailedDueToConnectionTimeout()
                     }
                     is UnknownHostException -> {
                         throw NetworkManagerClientExceptions.NoInternetConnectionException()
                     }
                     else -> {
                         throw NetworkManagerClientExceptions.NetworkRequestFailed(exception.message!!)
                     }
                 }
            }
        }
    }
}