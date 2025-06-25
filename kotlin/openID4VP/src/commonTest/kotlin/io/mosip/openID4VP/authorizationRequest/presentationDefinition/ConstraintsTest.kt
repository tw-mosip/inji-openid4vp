package io.mosip.openID4VP.authorizationRequest.presentationDefinition


import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import io.mosip.openID4VP.common.Logger
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test

class ConstraintsTest {

	@Before
	fun setUp() {
        mockkObject(Logger)
        every { Logger.error(any(), any(), any()) } answers {  }
	}

	@After
	fun tearDown() {
		clearAllMocks()
	}

	@Test
	fun `should throw invalid limit disclosure exception if limit disclosure is present and not matching with predefined values`() {
		val presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","format":{"ldp_vc":{"proof_type":["RsaSignature2018"]}},"constraints":{"fields":[{"path":["$.type"]}],"limit_disclosure": "not preferred"}}]}"""

		val expectedExceptionMessage =
			"Invalid Input: constraints->limit_disclosure value should be preferred"

		val actualException =
			Assert.assertThrows(AuthorizationRequestExceptions.InvalidLimitDisclosure::class.java) {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)

	}
}