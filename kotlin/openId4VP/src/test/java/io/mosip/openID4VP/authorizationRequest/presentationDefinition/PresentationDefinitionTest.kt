package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import android.util.Log
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.openID4VP.authorizationRequest.exception.AuthorizationRequestExceptions
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

class PresentationDefinitionTest {

    private lateinit var presentationDefinition: String
    private lateinit var expectedExceptionValue: String


    @Before
    fun setUp(){
        mockkStatic(Log::class)
        every { Log.e(any(), any()) } answers {
            val tag = arg<String>(0)
            val msg = arg<String>(1)
            println("Error: logTag: $tag | Message: $msg")
            0
        }
    }

    @After
    fun tearDown(){
        clearAllMocks()
    }

    @Test
    fun `should throw missing input exception if id param is missing`(){
        presentationDefinition =
            "{\"input_descriptors\":[{\"id\":\"id_123\",\"constraints\":{\"fields\":[{\"path\":[\"$.type\"]}]}}]}"
        expectedExceptionValue = "Missing Input: presentation_definition : id param is required"

        val actualException = assertThrows(AuthorizationRequestExceptions.MissingInput::class.java){validatePresentationDefinition(presentationDefinition)}

        assertEquals(expectedExceptionValue,actualException.message)
    }

    @Test
    fun `should throw missing input exception if input_descriptor param is missing`(){
        presentationDefinition =
            "{\"id\":\"pd_123\"}"
        expectedExceptionValue = "Missing Input: presentation_definition : input_descriptors param is required"

        val actualException = assertThrows(AuthorizationRequestExceptions.MissingInput::class.java){validatePresentationDefinition(presentationDefinition)}

        assertEquals(expectedExceptionValue,actualException.message)
    }

    @Test
    fun `should throw invalid input exception if id param value is empty or null`(){
        presentationDefinition =
            "{\"id\":\"\",\"input_descriptors\":[{\"id\":\"id_123\",\"constraints\":{\"fields\":[{\"path\":[\"\$.type\"]}]}}]}"
        expectedExceptionValue = "Invalid Input: presentation_definition : id value cannot be empty or null"

        val actualException = assertThrows(AuthorizationRequestExceptions.InvalidInput::class.java){validatePresentationDefinition(presentationDefinition)}

        assertEquals(expectedExceptionValue,actualException.message)
    }

    @Test
    fun `should throw missing input exception if input_descriptor param value is empty or null`(){
        presentationDefinition =
            "{\"id\":\"pd_123\",\"input_descriptors\":[]}"
        expectedExceptionValue = "Invalid Input: presentation_definition : input_descriptors value cannot be empty or null"

        val actualException = assertThrows(AuthorizationRequestExceptions.InvalidInput::class.java){validatePresentationDefinition(presentationDefinition)}

        assertEquals(expectedExceptionValue,actualException.message)
    }
}