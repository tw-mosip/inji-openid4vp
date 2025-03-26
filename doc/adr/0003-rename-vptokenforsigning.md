# 3. rename-VPtokenForSigning

Date: 2025-03-24

## Status

Accepted

## Context

The class VPTokenForSigning is used to represent a verifiable presentation token that will be signed by the consumer. But, this name has some issues:

- **Ambiguous Meaning**: The phrase "ForSigning" does not clearly indicate whether the token is already signed, in the process of being signed, or simply capable of being signed.

- **Redundant Wording**: "ForSigning" is an uncommon phrasing and does not align well with standard Class naming conventions.

- **Unclear Intent**: The name does not explicitly convey whether the class represents a raw, unsigned token or a helper for signing operations.

- **Lack of Readability**
## Decision

To improve clarity and maintainability, we will rename VPTokenForSigning to a more appropriate and intuitive name.

```
New Name: UnsignedVPToken
```

## Consequences

### Pros
- Improved Readability:

### Cons
- Minor changes required in the codebase & documentation to reflect the new name.
- Need for the consumers to update their codebase to reflect the new name.