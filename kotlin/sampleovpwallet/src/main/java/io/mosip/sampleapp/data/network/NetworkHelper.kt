package io.mosip.sampleapp.data.network

import io.mosip.sampleapp.data.api.VerifierApi
import io.mosip.sampleovpwallet.BuildConfig
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory

object NetworkHelper {
    private const val BASE_URL = BuildConfig.API_BASE_URL

    private val retrofit: Retrofit by lazy {
        Retrofit.Builder()
            .baseUrl(BASE_URL)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
    }

    val verifierApi: VerifierApi by lazy {
        retrofit.create(VerifierApi::class.java)
    }

}