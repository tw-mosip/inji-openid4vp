# INJI-OpenID4VP

## Installation

Snapshot builds are available - 

```
implementation "io.mosip:inji-openid4vp:0.2.0-SNAPSHOT"
```

## Create instance of OpenID4VP library to invoke it's methods
val openID4VP = OpenID4VP()

## APIs

### authenticateVerifier
- Receives a list of trusted verifiers & Verifier's encoded Authorization request from consumer app(mobile wallet).
- Decodes and parses the qr code data. Checks if the data contains request_uri or contains the entire Authorization request data entirely.
- Constructs the Authorization request object based on the client_id_scheme.
- Takes an optional boolean to toggle the client validation.
- Returns the validated Authorization request object.

```
 val authenticationResponse = openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: String, trustedVerifierJSON: List<Verifier>, shouldValidateClient: Bool)
```

###### Parameters

| Name                            | Type           | Description                                                                          | Sample                                                                                     |
|---------------------------------|----------------|--------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------|
| urlEncodedAuthorizationRequest  | String         | URL encoded query parameter string containing the Verifier's authorization request   | `"T1BFTklENFZQOi8vYXV0"`                                                                   |
| trustedVerifiers                | List<Verifier> | A list of trusted Verifier objects each containing a clientId and a responseUri list | `listOf(Verifier("https://verify.env1.net",listOf("https://verify.env1.net/responseUri"))` |
| shouldValidateClient            | Bool?          | Optional Boolean to toggle client validation for pre-registered client id scheme     | `true`                                                                                     |

###### Exceptions

**Exceptions**

1. DecodingException is thrown when there is an issue while decoding the Authorization Request
2. InvalidQueryParams exception is thrown if
   * query params are not present in the Request
   * there is an issue while extracting the params
   * both presentation_definition and presentation_definition_uri are present in Request
   * both presentation_definition and presentation_definition_uri are not present in Request
3. MissingInput exception is thrown if any of required params are not present in Request
4. InvalidInput exception is thrown if any of required params value is empty or null
5. InvalidVerifier exception is thrown if the received request client_iD & response_uri are not matching with any of the trusted verifiers
6. JWTVerification exception is thrown if there is any error in extracting public key, kid or signature verification failure.

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it. 

### constructVerifiablePresentation
- Receives a map of input_descriptor id & list of verifiable credentials for each input_descriptor that are selected by the end-user.
- Creates a vp_token without proof using received input_descriptor IDs and verifiable credentials, then returns its string representation to consumer app(mobile wallet) for signing it.

```
    val vpTokenWithoutProof = openID4VP.constructVerifiablePresentation(verifiableCredentials: Map<String, List<String>>)
```

###### Parameters

| Name                   | Type                       | Description                                                                                                      | Sample                                   |
|------------------------|----------------------------|------------------------------------------------------------------------------------------------------------------|------------------------------------------|
| verifiableCredentials  | Map<String, List<String>>  | A Map which contains input descriptor id as key and corresponding matching Verifiable Credentials list as value. | `mapOf("id_123" to listOf("vc1","vc2"))` |


###### Exceptions

1. JsonEncodingFailed exception is thrown if there is any issue while serializing the vp_token without proof.

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.

### shareVerifiablePresentation
- This function constructs a vp_token with proof using received VPResponseMetadata, then sends it and the presentation_submission to the Verifier via a HTTP POST request.
- Returns the response back to the consumer app(mobile app) saying whether it has received the shared Verifiable Credentials or not.

```
    val response = openID4VP.shareVerifiablePresentation(vpResponseMetadata: VPResponseMetadata)
```

###### Parameters

| Name                | Type                | Description                                                                             | Sample                                                                                                                                                             |
|---------------------|---------------------|-----------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| vpResponseMetadata  | VPResponseMetadata  | This contains domain & proof details such as jws, signatureAlgorithm, publicKey, domain | `VPResponseMetadata(jws = "eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ",signatureAlgorithm = "RsaSignature2018",publicKey = "publicKey",domain = "https://domain.net")")` |


###### Exceptions

1. JsonEncodingFailed exception is thrown if there is any issue while serializing the generating vp_token or presentation_submission class instances.
2. InterruptedIOException is thrown if the connection is timed out when network call is made.
3. NetworkRequestFailed exception is thrown when there is any other exception occurred when sending the response over http post request.

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.

### sendErrorToVerifier
- Receives an exception and sends it's message to the Verifier via an HTTP POST request.

```
 openID4VP.sendErrorToVerifier(exception: Exception)
```

###### Parameters

| Name      | Type      | Description                        | Sample                           |
|-----------|-----------|------------------------------------|----------------------------------|
| exception | Exception | This contains the exception object | `new Exception("exception message")` |


###### Exceptions

1. InterruptedIOException is thrown if the connection is timed out when network call is made.
2. NetworkRequestFailed exception is thrown when there is any other exception occurred when sending the response over http post request.