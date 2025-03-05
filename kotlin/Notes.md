## APIs exposed

1. authenticateVerifier

```authenticateVerifier(
   urlEncodedAuthorizationRequest: String,
   trustedVerifiers: List<Verifier>,
   shouldValidateClient: Boolean = false,
   ): AuthorizationRequest
   ```
2. constructVerifiablePresentationToken
```
constructVerifiablePresentationToken(verifiableCredentials: Map<String, Map<String, List<Any>>>): Map<String, String>
```
3. shareVerifiablePresentation
```
shareVerifiablePresentation(vpResponseMetadata: Map<String, VPResponseMetadata>): String
```
* uses authorizationRequest (output of authenticateVerifier)
* uses vpTokenForSigning (output of constructVerifiablePresentationToken)
* uses verifiableCredentials passed during constructVerifiablePresentationToken
4. sendErrorToVerifier
```
fun sendErrorToVerifier(exception: Exception)
``` 
* [used when consent is rejected by wallet user]
* uses responseUri set during authenticateVerifier call

#### Dependencies summary
1. share and construct api calls are dependent on other apis input / output
2. send error api is fully dependent on authenticateVerifier api

### Questions

1. Is it okay here to have these dependencies between apis?
2. Can consumers skip some api and call other apis? Eg - call send error without calling authenticate verifier -> take as input parameters
3. If yes, where should the data reside
   1. should it be kept as static (current auth response class stores this way) //Not so preferable
   2. How are we going to manage these ?

#### Others
1.  should format be got as string or FormatType from consumer (if got as formatType extra validation is not required, it will consumer's responsibility to handle this) -> Map<FormatType, VPResponseMetadata>
```
shareVerifiablePresentation(vpResponseMetadata: Map<String, VPResponseMetadata>)
```