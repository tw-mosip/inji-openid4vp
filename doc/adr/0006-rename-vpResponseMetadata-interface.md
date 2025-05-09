# 6. Rename VpResponseMetadata Interface and the implementing classes

Date: 2025-05-06

## People involved
- Swait Goel
- Alka Prasad
- Kiruthika

## Status

Accepted

## Context

The interface `VpResponseMetadata` is implemented by different formats of credentials and is responsible for holding the signature / proof of the UnSignedVPToken given by wallet. However, the current name implies that it contains some metadata for VP Response, which is misleading.

## Decision

To better align with the actual responsibility, the interface and implementing classes  will be renamed from `VpResponseMetadata` to `VpTokenSigningResult`. This new name clearly indicates that the utility of it is to store the result of signing the VpToken.

## Consequences

**Pros:**
- Improves code readability and maintainability by making the class name’s purpose explicit.

**Cons:**
- Requires updating all references to this class and object across the codebase to reflect the new name.
- Existing consumers to update their code as per this change