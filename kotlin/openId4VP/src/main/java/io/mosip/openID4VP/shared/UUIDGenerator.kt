package io.mosip.openID4VP.shared

import java.util.UUID
class UUIDGenerator {
    companion object {
        fun generateUUID(): String {
            return UUID.randomUUID().toString()
        }
    }
}