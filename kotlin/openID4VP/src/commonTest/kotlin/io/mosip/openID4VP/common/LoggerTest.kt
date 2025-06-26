package io.mosip.openID4VP.common

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import foundation.identity.jsonld.JsonLDObject
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.VPResponseMetadata
import kotlin.test.*

class LoggerTest {

	private lateinit var expectedValue: String
	private lateinit var expectedExceptionMessage: String
	private lateinit var actualException: Exception

	@BeforeTest
	fun setUp() {
		mockkObject(Logger)
		every { Logger.error(any(), any(), any()) } answers {}
		Logger.setTraceabilityId("test-openId4VP")
	}

	@AfterTest
	fun tearDown() {
		clearAllMocks()
	}

	@Test
	fun `should return log tag with library name and provided class name`() {
		expectedValue = "INJI-OpenID4VP : class name - LoggerTest | traceID - test-openId4VP"
		val logTag: String = Logger.getLogTag(this::class.simpleName!!)
		assertEquals(expectedValue, logTag)
	}

	@Test
	fun `should return missing input exception if exception type input value is MissingInput`() {
		expectedExceptionMessage =
			"Missing Input: parent field name->current field name param is required"
		actualException = Logger.handleException(
			exceptionType = "MissingInput",
			fieldPath = listOf("parent field name", "current field name"),
			className = this::class.simpleName!!
		)
		assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should return invalid input exception if exception type input value is InvalidInput and field data is of type String`() {
		expectedExceptionMessage =
			"Invalid Input: parent field name->current field name value cannot be an empty string, null, or an integer"
		actualException = Logger.handleException(
			exceptionType = "InvalidInput",
			fieldPath = listOf("parent field name", "current field name"),
			className = this::class.simpleName!!,
			fieldType = "String"
		)
		assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun `should return invalid input pattern exception if exception type input value is InvalidInputPattern`() {
		expectedExceptionMessage =
			"Invalid Input Pattern: parent field name->current field name pattern is not matching with OpenId4VP specification"
		actualException = Logger.handleException(
			exceptionType = "InvalidInputPattern",
			fieldPath = listOf("parent field name", "current field name"),
			className = this::class.simpleName!!
		)
		assertEquals(expectedExceptionMessage, actualException.message)
	}

	@Test
	fun name() {
		val abc = VPResponseMetadata(
			"test-id",
			"test-challenge",
			"test-state",
			"test-issuer",
		)

		val unsignedVPTokenMap = jacksonObjectMapper().writeValueAsString(abc)
		val vcJsonLdObject: JsonLDObject = JsonLDObject.fromJson(unsignedVPTokenMap)

		val message = vcJsonLdObject.toJson()
		println(message)

		// println(Json.encodeToString(vcJsonLdObject)) // not supported directly for JsonLDObject
	}
}
