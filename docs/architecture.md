# Architecture and decisions

## Problem boundary

The user is a developer sharing an agent failure with another engineer. The input is
structured JSONL plus a reviewed field policy. The output is a bundle that retains the
minimum approved execution metadata while removing or replacing other known fields.
Success means the real CLI can create a bundle, a fresh process can verify it, and negative
cases cannot silently carry unapproved fields into the export.

This addresses the export boundary, not trace collection, execution replay, or model evaluation.
The tool does not decide whether sharing is authorized or whether the retained metadata is safe.

```text
JSONL + reviewed policy
        |
 bounded parse / schema validation
        |
 deterministic transformation
        |
 in-memory artifact construction
        |
 exclusive new directory / manifest last
        |
 records + policy + count report + manifest
        |
 verify [separate approved policy] [source reproduction]
```

## Decision 1: Explicit retention instead of a detector

Regex and model-based classifiers can miss private text, particularly schema-specific values.
Here, strings may only be retained as approved enum members, replaced by aliases, masked, or
dropped. Unknown fields fail closed. This costs policy maintenance and rejects novel tool names
until reviewed, but makes the retention decision inspectable.

Masking or dropping a subtree is an intentional boundary: nested schema changes there do not
fail because no nested value is retained. Normal object traversal rejects unknown nested fields.
The policy is itself trusted configuration. An author can mistakenly approve a sensitive enum
or numeric field; strict parsing cannot solve that problem.

## Decision 2: Export-local aliases

A namespace-scoped in-memory map assigns `run-0001`, `run-0002`, and so on. It retains relationships
needed to diagnose a workflow without saving original IDs or a persistent correlation key.
Canonical object traversal and fixed record order make the transformation reproducible.

Tradeoff: changing input order can change aliases. Export-local sequential labels are linkable
within the bundle and may still enable re-identification using outside information. They are
neither a cryptographic privacy scheme nor an identity service. No secure memory wiping is claimed.

## Decision 3: Bounded batch validation before publication

The complete input is parsed and transformed in memory before the directory is created. This
avoids publishing a valid-looking prefix when a later record has an unknown field. Input and
output limits bound the batch size, though Python object memory exceeds serialized byte size.
This is deliberately not a streaming path for large telemetry archives.

Exclusive directory creation selects one writer if two processes target the same path. Files
use exclusive creation, and the manifest is written last. Readers must verify all four files;
directory existence alone is not completion. Process termination or an I/O error may leave partial
output. Retry uses a new directory; no destructive cleanup is automatic.

There is no fsync-based power-loss durability guarantee, transactional filesystem, or hostile
local-writer protection. On POSIX filesystems the requested directory mode is `0700`; Windows
mounts and existing parent access controls can have different behavior. Use a private working
directory and protect the original source independently.

## Decision 4: Separate integrity, policy trust, and reproduction

The manifest hashes exported artifacts only. It provides corruption detection, not authenticity.
A self-consistent rewritten bundle can pass hash verification. `--policy` compares the embedded
policy with a separate trusted file, preventing unnoticed policy substitution relative to that file.

Output checking verifies masked values, alias form, allowed fields, enum membership, numeric
bounds, and report structure. It cannot reconstruct the number of removed fields from output alone.
`--source` reruns the transformation and compares every artifact, checking those counts too.

We do not include an original-source digest: that would expose an additional fingerprint of private
input. Consequently, reproduction is not an assertion that the supplied source bytes are the exact
original bytes. Replacing one masked string with another illustrates this distinction.

## Questions and current answers

- **Can a newly added field slip through?** No outside intentionally masked/dropped subtrees;
  the whole export fails before output creation. This is tested with a last-record field addition.
- **Can diagnostics become another leak?** Expected data/filesystem errors use fixed text without
  source values or field names. This does not protect shell history, CLI syntax errors, process
  memory dumps, or an operator manually inspecting the original.
- **Can a hash check certify privacy?** No. The tests deliberately show the difference between
  self-consistent output, independently approved policy, and source reproduction.
- **Can retained metadata identify someone?** Possibly. Linkage, precise timing, rare enums, and
  record count remain visible. That risk needs data-specific review, not another hash.

## Deferred boundaries

No database is needed: the source already exists, and the output bundle is the useful durable
artifact. No UI, broker, cloud connection, credential lookup, or model call serves this initial
workflow. These are omissions by scope, not mocks of deployed infrastructure.
