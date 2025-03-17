package io.mosip.openID4VP.authorizationResponse.models.vpTokenForSigning

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.mosip.openID4VP.constants.FormatType

typealias VPTokensForSigning = Map<FormatType, VPTokenForSigning>

fun toJsonString(input: VPTokensForSigning): String? {
    val formattedMap = input.mapKeys { (key, _) -> key.value }
    val objectMapper = jacksonObjectMapper()

    return objectMapper.writeValueAsString(formattedMap)
}
