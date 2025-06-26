package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.exceptions.Exceptions
import io.mosip.openID4VP.exceptions.Exceptions.MissingInput
import kotlin.test.*

class InputDescriptorTest {
    private lateinit var presentationDefinition: String
    private lateinit var expectedExceptionMessage: String

    @BeforeTest
    fun setUp(){
        mockkObject(Logger)
        every { Logger.error(any(), any(), any()) } answers { }
    }

    @AfterTest
    fun tearDown(){
        clearAllMocks()
    }

    @Test
    fun `should throw missing input exception if id param is missing`() {
        presentationDefinition =
            """{"id":"id_123","input_descriptors":[{"constraints":{"fields":[{"path":["$.type"]}]}}]}"""
        expectedExceptionMessage = "Missing Input: input_descriptor->id param is required"

        val actualException = assertFailsWith<MissingInput> {
            deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
        }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw missing input exception if constraints param is missing`() {
        presentationDefinition =
            """{"id":"pd_123","input_descriptors":[{"id":"id_123"}]}"""
        expectedExceptionMessage = "Missing Input: input_descriptor->constraints param is required"

        val actualException = assertFailsWith<MissingInput> {
            deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
        }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid input exception if id param value is empty`() {
        presentationDefinition =
            """{"id":"pd_123","input_descriptors":[{"id":"","constraints":{"fields":[{"path":["$.type"]}]}}]}"""
        expectedExceptionMessage = "Invalid Input: input_descriptor->id value cannot be an empty string, null, or an integer"

        val actualException = assertFailsWith<Exceptions.InvalidInput> {
            deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
        }

        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid input exception if id param value is present but it's value is null`() {
        presentationDefinition =
            """{"id":"pd_123","input_descriptors":[{"id":null,"constraints":{"fields":[{"path":["$.type"]}]}}]}"""
        expectedExceptionMessage = "Invalid Input: input_descriptor->id value cannot be an empty string, null, or an integer"

        val actualException = assertFailsWith<Exceptions.InvalidInput> {
            deserializeAndValidate(presentationDefinition, PresentationDefinitionSerializer)
        }

        assertEquals(expectedExceptionMessage, actualException.message)
    }
}
