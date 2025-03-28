# 5. rename-constructVerifiablePresentationToken-method

Date: 2025-03-28

## Status

Accepted

## Context

The function constructVerifiablePresentationToken is responsible for handling a pre-requisite step (signing) before the actual creation of a VPToken. However, the current name implies that the function constructs a complete VPToken, which is misleading.

## Decision

The function constructVerifiablePresentationToken is responsible for handling a pre-requisite step (signing) before the actual creation of a VPToken. However, the current name implies that the function constructs a complete VPToken, which is misleading.

## Consequences

**Pros:**
- Improves code readability and maintainability by making the function’s purpose explicit.

**Cons:** 
- Requires updating all references to this function across the codebase to reflect the new name.
- Existing consumers to update their code as per this change