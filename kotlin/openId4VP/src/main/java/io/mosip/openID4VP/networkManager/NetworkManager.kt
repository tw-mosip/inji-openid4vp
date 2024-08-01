package io.mosip.openID4VP.networkManager

import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody

class NetworkManager {
    companion object{
         fun sendHttpPostRequest(requestBody: String, requestUrl: String): Response {
            val request = Request.Builder()
                .url(requestUrl)
                .post(requestBody.toRequestBody("application/x-www-form-urlencoded".toMediaType()))
                .build()

            val client = OkHttpClient()
           return client.newCall(request).execute()
        }
    }
}