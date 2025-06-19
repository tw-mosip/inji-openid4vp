package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp

import io.mosip.openID4VP.common.encodeToJsonString
import io.mosip.openID4VP.testData.ldpVPToken
import org.junit.Test


class LdpVPTokenBuilderTest {

    @Test
    fun name(){
        val ldpVPToken  = ldpVPToken.let {
                it as LdpVPToken
            }.copy(proof = null)

        val abc=  encodeToJsonString(ldpVPToken, "unsignedLdpVPToken", "className")
        println(abc)


    }
}
