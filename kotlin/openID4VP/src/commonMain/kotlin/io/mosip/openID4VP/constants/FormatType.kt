package io.mosip.openID4VP.constants

enum class FormatType(val value: String)  {
  LDP_VC("ldp_vc"),
  MSO_MDOC("mso_mdoc");

  companion object {
    fun fromValue(value: String): FormatType? {
      return FormatType.entries.find { it.value == value }
    }
  }
}

enum class VPFormatType(val value: String)  {
  LDP_VP("ldp_vp"),
  MSO_MDOC("mso_mdoc")
}