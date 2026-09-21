# Understanding ConfuserEx protection

ConfuserEx and its forks combine configurable transformations. Invisible symbol names, encrypted constants, control-flow dispatchers, reference proxies, and anti-tamper can occur independently. A familiar naming style alone is not sufficient evidence of a supported build.

For supported samples, CILantro interprets whole-section anti-tamper initialization to recover code, decodes supported constants, simplifies control flow, resolves call indirection where its target can be established, and renames eligible symbols for navigation.

Shared dispatcher computations can hide the state at a branch join. The cleanup pipeline separates supported shared tails and revisits constant/state propagation so more original branches become visible. Cases with unsupported exception or runtime state remain unchanged rather than receiving guessed destinations.

Reference-proxy recovery depends on whether binding can be established in the static model. The interpreter supports some dynamic delegate construction, but that does not establish support for every strong-proxy implementation or ConfuserEx fork. Dedicated encrypted-resource and packer coverage remains limited.

Both current analyst corpus outputs have no remaining detected method stubs, unresolved detected string uses, or dispatcher-like patterns. This is a result for those two samples, not a claim that every ConfuserEx configuration is completely unprotected.

Read [compatibility](compatibility.md) for the support boundary and [corpus validation](corpus.md) for the pinned fixtures. [Historical ConfuserEx research](history/pre-0.10/how-confuserex-works.md) preserves earlier implementation detail.
