package io.mosip.openID4VP.common

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean

class FieldDeserializer(
	private val jsonObject: JsonObject,
	private val className: String,
	private val parentField: String
) {
	fun <T> deserializeField(
		key: String,
		fieldType: String,
		deserializer: DeserializationStrategy<T>? = null,
		isMandatory: Boolean = false,
	): T? {
		val data = jsonObject[key]

		//field is mandatory but it is not present in the input
		if (data == null && isMandatory) {
			throw Logger.handleException(
				exceptionType = "MissingInput",
				fieldPath = listOf(parentField, key),
				className = className
			)
		} else if (data == JsonNull) {
			throw Logger.handleException(
				exceptionType = "InvalidInput",
				fieldPath = listOf(parentField, key),
				className = className,
				fieldType = fieldType
			)
		}
		//field is mandatory or optional and it is present in the input
		if (data != null) {
			val res = when {
				deserializer != null -> Json.decodeFromJsonElement(
					deserializer,
					data
				) // Custom fields
				fieldType == "String" -> (data as JsonPrimitive).content as T
				fieldType == "Boolean" -> (data as JsonPrimitive).boolean as T
				fieldType.startsWith("List") -> Json.decodeFromJsonElement(
					ListSerializer(String.serializer()),
					data
				) as T

				else -> throw SerializationException("Unsupported field type: $fieldType")
			}
			require(validateField(res, fieldType)) {
				throw Logger.handleException(
					exceptionType = "InvalidInput",
					fieldPath = listOf(parentField, key),
					className = className,
					fieldType = fieldType
				)
			}
			return res
		} else {
			return null
		}
	}
}