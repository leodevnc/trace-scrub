# Roadmap

## Implemented boundary

- Local JSONL input through policy validation to a separate bundle.
- Fail-closed object fields, bounded arrays, constrained scalar retention, masking, dropping,
  and export-local aliases.
- Independent verification with optional trusted policy and source reproduction.
- Bounded input/output, diagnostic value suppression, exclusive publication, partial-output refusal.
- Real subprocess workflow tests and targeted failure tests.

## Candidate extensions

These are design questions, not implemented features or scheduled commitments.

- **Policy change review:** produce a machine-readable diff showing newly retained fields and
  broadened numeric/enum ranges. Success would mean permissive changes cannot hide in formatting.
- **Coarsened timing:** explicitly bucket durations when precise timing is not necessary. This
  needs clear rounding behavior and data-specific utility/privacy review.
- **Format adapters:** map a documented agent trace format into this narrow JSONL schema. Preserve
  explicit rejection of unknown input fields; do not quietly discard adapter errors.

## Non-goals

Automatic legal compliance certification, generic secret detection, cross-export identity,
remote upload, hosted credentials, model-based privacy claims, and universal trace ingestion.
