# Trace Scrub

Export structured agent traces under an explicit field policy, without sending data to a service.

An agent developer investigating a failed tool call often needs to share execution order,
tool names, and timing, but not prompts, tool arguments, or returned documents. Trace Scrub
turns a local JSONL file and a reviewed policy into a separate, verifiable bundle. It leaves
the original file unchanged and refuses unknown fields instead of silently copying them.

This is a bounded local CLI, not a universal secret scanner or an anonymization guarantee.
It does not inspect free text with a model. The included traces are synthetic examples, not
recordings of a real agent or evidence of model quality.

## Run the example

Python 3.11 or later. No runtime dependencies, API keys, model calls, or network access.
From the repository root:

```sh
python3 -m trace_scrub export examples/traces.jsonl \
  --policy examples/policy.json --out demo-bundle

python3 -m trace_scrub verify demo-bundle \
  --policy examples/policy.json --source examples/traces.jsonl
```

The first command reports `{"exported":true,"records":3}`. The second reports
`verified`, `policy_verified`, and `source_verified` as `true`, with an explicit warning
that policy checks do not prove anonymity. Use a **new output directory** for each export;
existing directories are never overwritten.

Inspect `demo-bundle/records.jsonl`: the first two rows retain the same `run-0001` alias;
the third uses `run-0002`. Prompts and tool results become `[REDACTED]`, tool arguments
and debug data disappear, and approved event kinds, tool names, sequence values, and
durations remain. The Korean source prompt stays unchanged in the original file.

The bundle contains exactly four files:

| File | Purpose |
| --- | --- |
| `records.jsonl` | Transformed records, in original record order |
| `policy.json` | The field policy used for this export |
| `report.json` | Record count, action counts, and distinct aliases per namespace |
| `manifest.json` | SHA-256 hashes of the other three files; written last |

Neither original identifiers nor their lookup table are saved. No digest of the original
input is included. Review all four files before sharing; a policy itself can contain private
field names, enum values, or namespaces if its author puts them there.

## Define a policy

Every node must match exactly one of these forms. The root must be an object.

| Action | Fields besides `action` | Behavior |
| --- | --- | --- |
| `object` | `fields`, `required` | Visit explicitly named fields; reject unknown or missing required fields |
| `array` | `items`, `max_items` | Apply one rule to every element, with a length bound |
| `enum` | `values` | Retain only one of the approved strings |
| `number` | `min`, `max` | Retain a finite number in the inclusive range; booleans are not numbers |
| `boolean` | none | Retain only a JSON boolean |
| `alias` | `namespace` | Replace a nonempty string with an export-local sequential identifier |
| `mask` | none | Replace the entire value, including any nested subtree, with `[REDACTED]` |
| `drop` | none | Remove a named object field, including its entire subtree |

There is no unrestricted string-retention action. Numeric rules allow fractions; they do
not enforce integers, ordering, units, or relationships between records. Fields in `fields`
but absent from `required` are optional. A required dropped field must exist in the source
but is absent from the output. `drop` is not allowed at the root or as an array item rule.

Aliases share equality within a namespace across all records. Namespaces are independent.
Assignments depend on first encounter, with object keys visited in sorted order. Each export
resets the map; the same `run-0001` label in two exports does **not** establish identity.
Aliases preserve linkage within an export and are not cryptographic pseudonyms.

See [the example policy](examples/policy.json) for nested tool calls. Start by masking or
dropping source text; explicitly approve only fields needed for diagnosis. A schema change
outside a masked/dropped subtree requires a deliberate policy update.

## Verification and failure behavior

- `verify bundle` checks the file set, hashes, output policy, and report shape. It trusts
  the embedded policy; hashes detect corruption, not a malicious author rewriting the bundle.
- `--policy approved.json` additionally compares against an independently trusted policy,
  ignoring JSON whitespace and object-key order. Keep this file outside the bundle's trust boundary.
- `--source original.jsonl` additionally reproduces the transformation and action counts.
  This proves reproduction, **not byte-for-byte original source identity**: changes to masked
  text can legitimately produce identical output.
- Validation errors return exit code `2`, with a fixed diagnosis and sometimes a record number.
  Source values, source field names, and filesystem exception details are not echoed.
  CLI syntax errors are handled by argparse; do not pass private text as command-line arguments.
- All records are validated before creating the output directory. A validation failure creates
  no bundle. An I/O failure can leave a partial directory; do not share it. Verify completion,
  inspect the failure, and retry into a new directory. The program never deletes prior output.

Input is limited to 8 MiB, 2,000 records, 64 KiB per JSONL line, and 20 JSON nesting levels.
Policies are limited to 64 KiB on export, 256 nodes, and 12 rule nesting levels. Arrays permit
at most 1,000 items per rule, enums at most 100 short strings, and aliases at most 256 input
characters. Duplicate JSON keys, blank lines, invalid UTF-8, non-finite numbers, and symbolic
link input files are rejected. Output is also size-bounded. See [architecture](docs/architecture.md)
for trust assumptions and publication details.

## Scope and limitations

- Intended for local structured traces, not arbitrary log formats, OTLP ingestion, or live streaming.
- Approved numbers, enums, field presence, record order, and alias relationships can still reveal
  sensitive information. Data classification and sharing authorization remain human decisions.
- No pattern detector, LLM classifier, encryption, differential privacy, secure memory erasure,
  or formal de-identification claim. Unknown private values inside an approved numeric range
  are not automatically detected.
- Filesystem access is assumed to be local and trusted. Symlink checks are not a defense against
  a hostile process racing path changes. Directory permissions depend on the host filesystem.
- No persistence of raw traces beyond the supplied source, no telemetry, no background worker,
  and no model-provider dependency. A future model-assisted review would need a separate opt-in
  provider boundary; it is not part of this implementation.

## Development

```sh
python3 -m unittest discover -s tests -v
```

An optional installed command is available via `python3 -m pip install .` in a virtual
environment. Packaging requires setuptools 68 or later. Running directly with `python3 -m`
does not require installing or downloading anything.

- [Design choices and questions](docs/architecture.md)
- [Reproducible checks and observations](docs/testing.md)
- [Bounded roadmap](docs/roadmap.md)

MIT licensed.
