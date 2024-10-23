# INJI-openId4VP

Description: Implementation of OpenID4VP protocols in Kotlin

## Functionalities

- Decode and parse the Verifier's encoded Authorization Request received from the Wallet.
- Authenticates the Verifier using the received clientId and returns the valid Presentation Definition to the Wallet.
- Receives the list of verifiable credentials(VC's) from the Wallet which are selected by the Wallet end user based on the credentials requested as part of Verifier Authorization request.
- Constructs the verifiable presentation and send it to wallet for generating Json Web Signature (JWS).
- Receives the signed Verifiable presentation and sends a POST request with generated vp_token and presentation_submission to the Verifier response_uri endpoint.

**Note** : Fetching Verifiable Credentials by passing [Scope](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-using-scope-parameter-to-re) param in Authorization Request is not supported by this library. 

## Installation

Snapshot builds are available - 

```
implementation "io.mosip:inji-openID4VP:0.1.0-SNAPSHOT"
```

## Create instance of OpenId4VP library to invoke it's methods
val openID4VP = OpenID4VP()

## APIs

### authenticateVerifier
- Receives a list of trusted verifiers & Verifier's encoded Authorization request from Wallet.
- Decodes and parse the request, extracts the clientId and verifies it against trusted verifier's list clientId.
- Returns the Authentication response which contains validated Presentation Definition of the Authorization request.

```
 val authenticationResponse = openID4VP.authenticateVerifier(encodedAuthenticationRequest: String, trustedVerifierJSON: List<Verifier>)
```

###### Parameters

| Name                         | Type           | Description                                                                          | Sample                                                                                     |
|------------------------------|----------------|--------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------|
| encodedAuthenticationRequest | String         | Base64 encoded string containing the Verifier's authorization request                | `"T1BFTklENFZQOi8vYXV0"`                                                                   |
| trustedVerifiers             | List<Verifier> | A list of trusted Verifier objects each containing a clientId and a responseUri list | `listOf(Verifier("https://verify.env1.net",listOf("https://verify.env1.net/responseUri"))` |


###### Exceptions

1. DecodingException is thrown when there is and issue while decoding the Authorization Request
2. InvalidQueryParams exception is thrown if 
   * query params are not present in the Request
   * there is an issue while extracting the params 
   * presentation_definition is not present in Request
3. InvalidInput exception is thrown if any of required params value is empty
4. InvalidVerifierClientID exception is thrown if the received request client_iD & response_uri are not matching with any of the trusted verifiers

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it. 
   


### constructVerifiablePresentation
- Receives a map of input_descriptor id & list of verifiable credentials for each input_descriptor.
- Creates a Verifiable Presentation token without proof from received input_descriptor IDs and verifiable credentials, then returns it's string representation to Wallet for signing it.

```
    let vpTokenWithoutProof = openID4VP.constructVerifiablePresentation(verifiableCredentials: Map<String, List<String>>)
```

###### Parameters

| Name                   | Type                       | Description                                                                                                      | Sample                                   |
|------------------------|----------------------------|------------------------------------------------------------------------------------------------------------------|------------------------------------------|
| verifiableCredentials  | Map<String, List<String>>  | A Map which contains input descriptor id as key and corresponding matching Verifiable Credentials list as value. | `mapOf("id_123" to listOf("vc1","vc2"))` |


###### Exceptions

1. JsonEncodingException is thrown if there is any issue while serializing the Verifiable Presentation token without proof.

### shareVerifiablePresentation
- This function constructs a verifiable presentation token with proof using received VPResponseMetadata, then sends it and the presentation submission to the Verifier via a HTTP POST request.
- Returns the response with a success or error message back to the wallet.

```
    let response = openID4VP.shareVerifiablePresentation(vpResponseMetadata: VPResponseMetadata)
```

###### Parameters

| Name                | Type                | Description                                                                             | Sample                                                                                                                                                             |
|---------------------|---------------------|-----------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| vpResponseMetadata  | VPResponseMetadata  | This contains domain & proof details such as jws, signatureAlgorithm, publicKey, domain | `VPResponseMetadata(jws = "eyJiweyrtwegrfwwaBKCGSwxjpa5suaMtgnQ",signatureAlgorithm = "RsaSignature2018",publicKey = "publicKey",domain = "https://domain.net")")` |


###### Exceptions

1. JsonEncodingException is thrown if there is any issue while serializing the Verifiable Presentation token or Presentation Submission class instances.
2. InterruptedIOException is thrown if the connection is timed out when network call is made.
3. NetworkRequestFailed exception is thrown when there is any other exception occurred when sending the response over http post request.

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.

### sendErrorToVerifier
- Receives an exception and sends it's message to the Verifier via a HTTP POST request.

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