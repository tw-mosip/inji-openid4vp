package io.mosip.openID4VP.networkManager

import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.io.InterruptedIOException

private val logTag = Logger.getLogTag(NetworkManagerClient::class.simpleName!!)

class NetworkManagerClient {
    companion object {
        fun sendHTTPRequest(
            url: String,
            method: HttpMethod,
            bodyParams: Map<String, Any>? = null,
            headers: Map<String, String>? = null
        ): Map<String, Any> {
            try {
                val client = OkHttpClient.Builder().build()
                val request: Request
                when (method) {
                    HttpMethod.POST -> {
                        val requestBuilder = Request.Builder().url(url)
                        if (bodyParams != null) {
                            val formBodyBuilder = FormBody.Builder()
                            processFormParams(bodyParams, formBodyBuilder)
                            val requestBody = formBodyBuilder.build()
                            requestBuilder.post(requestBody)
                        } else {
                            requestBuilder.post(FormBody.Builder().build())
                        }
                        headers?.forEach { (key, value) ->
                            requestBuilder.addHeader(key, value)
                        }
                        request = requestBuilder.build()
                    }
                    HttpMethod.GET -> request = Request.Builder().url(url).get().build()
                }
                val response: Response = client.newCall(request).execute()

                if (response.isSuccessful) {
                    val body = response.body?.byteString()?.utf8()
                        ?: ""

                    return mapOf(
                        "body" to body,
                        "header" to response.headers
                    )
                } else {
                    throw Exception(response.toString())
                }
            } catch (exception: InterruptedIOException) {
                val specificException =
                    NetworkManagerClientExceptions.NetworkRequestTimeout()
                Logger.error(logTag, specificException)
                throw specificException
            } catch (exception: Exception) {
                val specificException =
                    NetworkManagerClientExceptions.NetworkRequestFailed(
                        exception.message ?: "Unknown error"
                    )
                Logger.error(logTag, specificException)
                throw specificException
            }

        }

        private fun processFormParams(
            params: Map<String, Any>,
            formBodyBuilder: FormBody.Builder,
            prefix: String = ""
        ) {
            params.forEach { (key, value) ->
                val formKey = if (prefix.isNotEmpty()) "$prefix[$key]" else key
                when (value) {
                    is Map<*, *> -> {
                        processFormParams(value as Map<String, Any>, formBodyBuilder, formKey)
                    }

                    is List<*> -> {
                        value.forEachIndexed { index, item ->
                            val listKey = "$formKey[$index]"
                            when (item) {
                                is Map<*, *> -> {
                                    processFormParams(
                                        item as Map<String, Any>,
                                        formBodyBuilder,
                                        listKey
                                    )
                                }

                                else -> formBodyBuilder.add(listKey, item.toString())
                            }
                        }
                    }

                    else -> formBodyBuilder.add(formKey, value.toString())
                }
            }
        }
    }

}
