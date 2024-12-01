import kotlinx.serialization.json.JsonNull

fun validateField(field: Any?, fieldType: String?): Boolean {
	var res = true
	when {
		fieldType == "String" -> res = field.toString().isNotEmpty() && field != JsonNull

		fieldType?.startsWith("List") == true -> res =
			field != JsonNull && (field as? List<*>)?.isNotEmpty() ?: false

		fieldType == "Boolean" -> res = field != JsonNull && (field == true || field == false)
	}
	return res
}