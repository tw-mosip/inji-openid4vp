package io.mosip.openID4VP.constants

import com.fasterxml.jackson.annotation.JsonValue

enum class FormatType(@JsonValue val value: String)  {
  LDP_VC("ldp_vc")
}