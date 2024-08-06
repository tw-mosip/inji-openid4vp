package io.mosip.openID4VP.shared

import java.util.UUID
object UUIDGenerator {
    fun generateUUID(): String {
        return UUID.randomUUID().toString()
    }
}