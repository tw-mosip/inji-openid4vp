package io.mosip.sampleapp.utils

import io.mosip.openID4VP.constants.VCFormatType
import io.mosip.sampleapp.data.VCMetadata

object Utils {
    fun getDisplayLabel(vcMetadata: VCMetadata): String? {
        val typeLabel = when (vcMetadata.format) {
            VCFormatType.LDP_VC.value -> {
                val typeArray = vcMetadata.vc.getAsJsonArray("type")
                if (typeArray != null && typeArray.size() > 1) {
                    typeArray[1].asString
                } else {
                    "-"
                }
            }

            VCFormatType.MSO_MDOC.value -> {
                "MDL Driving License"
            }

            else -> "-"
        }
        return typeLabel
    }
}