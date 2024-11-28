fun isNeitherNullNorEmpty(field: String?): Boolean {
	return field != "null" && !field.isNullOrEmpty()
}