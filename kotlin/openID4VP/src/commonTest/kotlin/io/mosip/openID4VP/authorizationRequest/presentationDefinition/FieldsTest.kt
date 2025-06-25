package io.mosip.openID4VP.authorizationRequest.presentationDefinition


import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions.InvalidInputPattern
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.exceptions.Exceptions
import io.mosip.openID4VP.exceptions.Exceptions.MissingInput

import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test

class FieldsTest {
	private lateinit var presentationDefinition: String
	private lateinit var expectedExceptionMessage: String

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
	fun `should throw invalid input pattern exception for invalid path param prefix`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":["$-type"]}]}}]}"""
		expectedExceptionMessage =
			"Invalid Input Pattern: fields->path pattern is not matching with OpenId4VP specification"

		val actualException =
			Assert.assertThrows(InvalidInputPattern::class.java) {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw missing input exception if path param is missing`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{}]}}]}"""
		expectedExceptionMessage = "Missing Input: fields->path param is required"

		val actualException =
			Assert.assertThrows(MissingInput::class.java) {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw invalid input exception if path param is empty`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":[]}]}}]}"""
		expectedExceptionMessage = "Invalid Input: fields->path value cannot be empty or null"

		val actualException =
			Assert.assertThrows(Exceptions.InvalidInput::class.java) {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should throw invalid input exception if path param is present but it's value is null`() {
		presentationDefinition =
			"""{"id":"pd_123","input_descriptors":[{"id":"id_123","constraints":{"fields":[{"path":null}]}}]}"""
		expectedExceptionMessage = "Invalid Input: fields->path value cannot be empty or null"

		val actualException =
			Assert.assertThrows(Exceptions.InvalidInput::class.java) {
				deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
			}

		Assert.assertEquals(expectedExceptionMessage, actualException.message)
	}
}
