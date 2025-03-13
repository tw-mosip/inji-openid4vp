package io.mosip.openID4VP.common

enum class ClientIdScheme(val value: String) {
    PRE_REGISTERED("pre-registered"),
    REDIRECT_URI("redirect_uri"),
    DID("did")
}

enum class ResponseMode(val value: String) {
    DIRECT_POST("direct_post"),
    DIRECT_POST_JWT("direct_post.jwt"),
}