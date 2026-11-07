# Reproducible checks

Run on Python 3.11 or later from the repository root:

```sh
python3 -m unittest discover -s tests -v
```

The suite contains 26 tests. It uses temporary directories and synthetic strings, does not read
credentials, and makes no network requests. CLI tests launch real Python subprocesses; source
transformation and bundle verification are not mocked. One I/O failure test injects an `OSError`
while writing `report.json` to exercise incomplete-publication behavior.

| Area | Evidence |
| --- | --- |
| Complete local workflow | Export CLI, separate verify process, approved policy and source reproduction, unchanged multilingual source |
| Retention rules | Nested unknown fields, required fields, enum/range/type restrictions, array limit, whole-subtree masking/drop |
| Alias behavior | Equality within namespace, separation across namespaces, reset across exports, deterministic artifacts |
| Input validation | Duplicate keys, NaN/Infinity/overflow, invalid Unicode, UTF-16 rejection, line/file/record/depth limits |
| Policy validation | Unknown actions, unexpected options, invalid bounds, illegal drop placement, rule count/depth limits |
| Publication failure | Existing directory refusal, two real concurrent publishers, injected partial write and fresh-directory recovery |
| Integrity and trust | Corrupted bytes, unexpected files, symlink inputs, rehashed raw-value insertion, substituted policy |
| Reproduction | Altered counts detected with source; masked-text changes intentionally do not prove original source identity |
| Error disclosure | Private sentinels absent from diagnostics and exported artifacts |

## Manual exercise

```sh
python3 -m trace_scrub export examples/traces.jsonl \
  --policy examples/policy.json --out demo-bundle
python3 -m trace_scrub verify demo-bundle \
  --policy examples/policy.json --source examples/traces.jsonl
```

Expected: three exported records, two run aliases, five mask actions, and three dropped fields.
The bundle contains none of the `SYNTHETIC_` private-value sentinels. Policy field names for
dropped fields still appear in `policy.json`; field names are configuration, not removed source
values. Review policy content too.

Use a disposable copy of the example to add an unapproved field to its last record. Export to a
new directory should exit `2` without creating that directory. A second export into an existing
bundle should exit `2` without changing any file.

## Isolated package check

With setuptools 68 or later and wheel already available locally:

```sh
source_dir="$PWD"
package_dir=$(mktemp -d /tmp/trace-scrub-package.XXXXXX)
python3 -m pip wheel --no-deps --no-build-isolation --no-index \
  --wheel-dir "$package_dir" .
python3 -m venv "$package_dir/venv"
"$package_dir/venv/bin/python" -m pip install --no-index --no-deps \
  "$package_dir/trace_scrub-0.1.0-py3-none-any.whl"
cd "$package_dir"
"$package_dir/venv/bin/trace-scrub" export "$source_dir/examples/traces.jsonl" \
  --policy "$source_dir/examples/policy.json" --out "$package_dir/bundle"
"$package_dir/venv/bin/trace-scrub" verify "$package_dir/bundle" \
  --policy "$source_dir/examples/policy.json" --source "$source_dir/examples/traces.jsonl"
```

This checks packaging and the installed entry point independently of the source working
directory. It is not a throughput benchmark. The temporary directory is retained for inspection.

## Observations and limits of the evidence

The last-record failure case shows why bounded whole-batch validation is useful: errors do not
leave a seemingly usable output prefix. The report-tampering case shows why source-free structural
checking cannot establish removed-field counts. The policy-substitution case shows why embedded
configuration is not its own trust anchor.

These checks establish behavior for explicit rules and synthetic cases, not a false-negative rate
for arbitrary sensitive data. There is no model-quality evaluation because this tool has no model.
Hostile filesystem races, crash-on-power-loss durability, large-scale ingestion, and whether a real
organization's disclosure policy is sufficient are not verified here.
