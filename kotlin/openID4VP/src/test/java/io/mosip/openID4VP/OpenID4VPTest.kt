package io.mosip.openID4VP

import io.mockk.every
import io.mockk.mockkObject
import io.mockk.verify
import io.mosip.openID4VP.exceptions.Exceptions
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.testData.setField
import org.junit.Before
import org.junit.Test

class OpenID4VPTest {
    val openID4VP = OpenID4VP(traceabilityId = "OpenID4VPTest")

    @Before
    fun setUp() {
        mockkObject(NetworkManagerClient)
        setField(
            openID4VP,
            "responseUri",
            "https://mock-verifier.com/response-uri"
        )
    }

    @Test
    fun `should send the error to verifier when sendErrorToVerifier is called`() {
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/response-uri",
                HTTP_METHOD.POST,
                any()
            )
        } returns mapOf("body" to "VP share success")

        openID4VP.sendErrorToVerifier(Exceptions.InvalidData("Unsupported response_mode"))

        verify {
            NetworkManagerClient.sendHTTPRequest(
                url = "https://mock-verifier.com/response-uri",
                method = HTTP_METHOD.POST,
                bodyParams = mapOf("error" to "Unsupported response_mode"),
            )
        }
    }
}