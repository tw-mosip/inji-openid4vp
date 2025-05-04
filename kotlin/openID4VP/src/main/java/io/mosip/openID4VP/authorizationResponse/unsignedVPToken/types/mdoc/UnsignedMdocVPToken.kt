package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc

import co.nstant.`in`.cbor.model.DataItem
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.cborArrayOf
import io.mosip.openID4VP.common.cborMapOf
import io.mosip.openID4VP.common.createHashedDataItem
import io.mosip.openID4VP.common.encodeCbor
import io.mosip.openID4VP.common.getMdocDocType
import io.mosip.openID4VP.common.tagEncodedCbor
import io.mosip.openID4VP.common.toHex

data class UnsignedMdocVPToken(
    val unsignedDeviceAuth: Map<String, Any>
) : UnsignedVPToken
