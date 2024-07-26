package io.mosip.openID4VP.dto

data class Verifier(val clientId: String,val responseUri: List<String>)