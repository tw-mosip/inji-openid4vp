# 4.Change structure for Format field in PresentationDefinition and InputDescriptor

Date: 2025-03-27

## Status

Accepted

## Context

The class Format in the PresentationDefinition and InputDescriptor class is used to represent the format of the verifiable credentials supported by the verifier along with their signing algorithm. But, this class has some issues: 

- **Extensibility**: The current implementation is tightly coupled with the specific credential format logic is not abstracted out. This makes it difficult to add support for new credential formats. 

## Decision

To improve extensibility and  maintainability, we will accept format as a Map of String to Object which will make it easier to extend

