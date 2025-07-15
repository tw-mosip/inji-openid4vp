package io.mosip.openID4VP.common

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper

object JacksonObjectMapper {
    val instance: ObjectMapper = jacksonObjectMapper()
}