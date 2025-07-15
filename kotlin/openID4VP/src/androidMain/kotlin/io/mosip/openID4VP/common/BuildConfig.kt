package io.mosip.openID4VP.common

import android.os.Build

object BuildConfig {
    fun getVersionSDKInt(): Int {
        return Build.VERSION.SDK_INT
    }
}