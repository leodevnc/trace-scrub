import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path


MAX_FILE = 8 * 1024 * 1024
MAX_LINE = 64 * 1024
MAX_RECORDS = 2000
MASK = "[REDACTED]"
FILES = {"records.jsonl", "policy.json", "report.json", "manifest.json"}


class Invalid(ValueError):
    """Diagnostics are fixed messages and never echo input values or field names."""


def encode(value):
    try:
        return (json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                           separators=(",", ":")) + "\n").encode("utf-8")
    except (ValueError, TypeError, RecursionError, UnicodeError) as error:
        raise Invalid("value cannot be encoded as bounded UTF-8 JSON") from error


def bounded(value, depth=0):
    if depth > 20:
        raise Invalid("JSON nesting exceeds 20 levels")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise Invalid("object keys must be strings")
            bounded(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            bounded(item, depth + 1)
    elif isinstance(value, float) and not math.isfinite(value):
        raise Invalid("non-finite numbers are not accepted")


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Invalid("duplicate JSON keys are not accepted")
            result[key] = value
        return result

    def constant(_):
        raise Invalid("non-finite numbers are not accepted")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
        bounded(value)
        encode(value)
        return value
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Invalid("invalid or unsupported UTF-8 JSON") from error


def read(path, limit=MAX_FILE):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise Invalid("input must be an existing regular file, not a symlink")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise Invalid("file exceeds its size limit")
    return raw


def parse_records(raw):
    if len(raw) > MAX_FILE:
        raise Invalid("dataset exceeds 8 MiB")
    result = []
    for number, line in enumerate(raw.splitlines(), 1):
        if not line.strip() or len(line) > MAX_LINE:
            raise Invalid(f"record {number}: blank or oversized line")
        try:
            value = decode(line)
        except Invalid as error:
            raise Invalid(f"record {number}: invalid or unsupported JSON") from error
        if not isinstance(value, dict):
            raise Invalid(f"record {number}: expected an object")
        result.append(value)
        if len(result) > MAX_RECORDS:
            raise Invalid("dataset exceeds 2000 records")
    if not result:
        raise Invalid("dataset cannot be empty")
    return result


def validate_policy(policy):
    count = 0

    def visit(node, depth=0, allow_drop=False):
        nonlocal count
        count += 1
        if count > 256 or depth > 12:
            raise Invalid("policy exceeds node or depth limit")
        if not isinstance(node, dict) or not isinstance(node.get("action"), str):
            raise Invalid("each policy node requires an action")
        action = node["action"]
        fields = {
            "object": {"action", "fields", "required"}, "array": {"action", "items", "max_items"},
            "enum": {"action", "values"}, "number": {"action", "min", "max"},
            "boolean": {"action"}, "mask": {"action"}, "drop": {"action"},
            "alias": {"action", "namespace"},
        }
        if action not in fields or node.keys() != fields[action]:
            raise Invalid("unknown action or unexpected policy fields")
        if action == "object":
            mapping, required = node["fields"], node["required"]
            if not isinstance(mapping, dict) or not isinstance(required, list):
                raise Invalid("invalid object policy")
            if any(not isinstance(key, str) or not key or len(key) > 128 for key in mapping):
                raise Invalid("invalid policy field name")
            if any(not isinstance(key, str) for key in required) or len(set(required)) != len(required) or not set(required) <= mapping.keys():
                raise Invalid("invalid required field list")
            for key in sorted(mapping):
                visit(mapping[key], depth + 1, True)
        elif action == "array":
            if type(node["max_items"]) is not int or not 0 <= node["max_items"] <= 1000:
                raise Invalid("array max_items must be an integer from 0 to 1000")
            visit(node["items"], depth + 1)
        elif action == "enum":
            values = node["values"]
            if not isinstance(values, list) or not 1 <= len(values) <= 100 or any(not isinstance(v, str) or len(v) > 128 for v in values):
                raise Invalid("enum requires 1-100 short string values")
            if len(set(values)) != len(values):
                raise Invalid("enum contains duplicate values")
        elif action == "number":
            if any(type(node[key]) not in (int, float) or
                   (type(node[key]) is float and not math.isfinite(node[key]))
                   for key in ("min", "max")) or node["min"] > node["max"]:
                raise Invalid("number requires finite ordered min/max bounds")
        elif action == "alias":
            if not isinstance(node["namespace"], str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", node["namespace"]):
                raise Invalid("alias namespace must be a short lowercase identifier")
        elif action == "drop" and not allow_drop:
            raise Invalid("drop is supported only for named object fields")

    visit(policy)
    if policy["action"] != "object":
        raise Invalid("root policy must be an object")
    return policy


class Transformer:
    def __init__(self, policy):
        self.policy = validate_policy(policy)
        self.aliases = {}
        self.counts = Counter()

    def apply(self, node, value):
        action = node["action"]
        self.counts[action] += 1
        if action == "drop":
            return None
        if action == "mask":
            return MASK
        if action == "object":
            if not isinstance(value, dict):
                raise Invalid("expected object")
            if value.keys() - node["fields"].keys():
                raise Invalid("unknown input field; export refused")
            if not set(node["required"]) <= value.keys():
                raise Invalid("required input field is missing")
            result = {}
            for key in sorted(value):
                rule = node["fields"][key]
                transformed = self.apply(rule, value[key])
                if rule["action"] != "drop":
                    result[key] = transformed
            return result
        if action == "array":
            if not isinstance(value, list) or len(value) > node["max_items"]:
                raise Invalid("expected a bounded array")
            return [self.apply(node["items"], item) for item in value]
        if action == "enum":
            if not isinstance(value, str) or value not in node["values"]:
                raise Invalid("value is outside the approved enum")
            return value
        if action == "number":
            if type(value) not in (int, float) or not node["min"] <= value <= node["max"]:
                raise Invalid("value is outside the approved numeric range")
            return value
        if action == "boolean":
            if type(value) is not bool:
                raise Invalid("expected boolean")
            return value
        if not isinstance(value, str) or not 1 <= len(value) <= 256:
            raise Invalid("alias input must be a nonempty string of at most 256 characters")
        namespace = node["namespace"]
        mapping = self.aliases.setdefault(namespace, {})
        return mapping.setdefault(value, f"{namespace}-{len(mapping) + 1:04d}")

    def transform(self, records):
        result = []
        for number, record in enumerate(records, 1):
            try:
                result.append(self.apply(self.policy, record))
            except Invalid as error:
                raise Invalid(f"record {number}: {error}") from error
        return result


def artifacts(records, policy):
    transformer = Transformer(policy)
    transformed = transformer.transform(records)
    data = {
        "records.jsonl": b"".join(encode(row) for row in transformed),
        "policy.json": encode(policy),
        "report.json": encode({"records": len(records), "actions": dict(transformer.counts),
                               "alias_groups": {key: len(value) for key, value in transformer.aliases.items()}}),
    }
    if any(len(raw) > MAX_FILE for raw in data.values()) or any(len(encode(row)) > MAX_LINE for row in transformed):
        raise Invalid("transformed output exceeds size limits")
    data["manifest.json"] = encode({"format_version": 1, "files": {
        name: hashlib.sha256(raw).hexdigest() for name, raw in data.items()}})
    return data


def export(source, policy_path, output):
    records = parse_records(read(source))
    policy = validate_policy(decode(read(policy_path, 65536)))
    data = artifacts(records, policy)
    directory = Path(output)
    directory.mkdir(mode=0o700)
    # Manifest is the last completion marker; partial writes are never called complete.
    for name, raw in data.items():
        with (directory / name).open("xb") as stream:
            stream.write(raw)
    return {"exported": True, "records": len(records)}


def check_output(node, value):
    action = node["action"]
    if action == "object":
        allowed = {key for key, rule in node["fields"].items() if rule["action"] != "drop"}
        required = set(node["required"]) & allowed
        if not isinstance(value, dict) or value.keys() - allowed or not required <= value.keys():
            raise Invalid("output object violates policy")
        for key, item in value.items():
            check_output(node["fields"][key], item)
    elif action == "array":
        if not isinstance(value, list) or len(value) > node["max_items"]:
            raise Invalid("output array violates policy")
        for item in value:
            check_output(node["items"], item)
    elif action == "mask":
        if value != MASK:
            raise Invalid("output mask is missing")
    elif action == "alias":
        if not isinstance(value, str) or not re.fullmatch(re.escape(node["namespace"]) + r"-[0-9]{4,}", value):
            raise Invalid("output alias is invalid")
    else:
        Transformer({"action": "object", "fields": {}, "required": []}).apply(node, value)


def verify(directory, source=None, policy_path=None):
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir() or {p.name for p in directory.iterdir()} != FILES:
        raise Invalid("bundle is incomplete or contains unexpected files")
    data = {name: read(directory / name) for name in FILES}
    manifest = decode(data["manifest.json"])
    expected = {"format_version": 1, "files": {name: hashlib.sha256(raw).hexdigest()
                for name, raw in data.items() if name != "manifest.json"}}
    if encode(manifest) != encode(expected):
        raise Invalid("manifest or artifact digest mismatch")
    policy = validate_policy(decode(data["policy.json"]))
    if policy_path is not None:
        approved = validate_policy(decode(read(policy_path, 65536)))
        if encode(approved) != encode(policy):
            raise Invalid("bundle policy differs from the supplied policy")
    rows = parse_records(data["records.jsonl"])
    for row in rows:
        check_output(policy, row)
    report = decode(data["report.json"])
    if not isinstance(report, dict) or report.keys() != {"records", "actions", "alias_groups"} or type(report["records"]) is not int or report["records"] != len(rows):
        raise Invalid("invalid report")
    actions, namespaces = set(), set()

    def collect(node):
        actions.add(node["action"])
        if node["action"] == "alias":
            namespaces.add(node["namespace"])
        elif node["action"] == "object":
            for child in node["fields"].values():
                collect(child)
        elif node["action"] == "array":
            collect(node["items"])

    collect(policy)
    for key, allowed in (("actions", actions), ("alias_groups", namespaces)):
        if not isinstance(report[key], dict) or report[key].keys() - allowed or any(type(n) is not int or n < 0 for n in report[key].values()):
            raise Invalid("invalid report counts")
    if source is not None:
        expected_data = artifacts(parse_records(read(source)), policy)
        if data != expected_data:
            raise Invalid("bundle does not reproduce from the supplied source")
    return {"verified": True, "records": len(rows), "source_verified": source is not None,
            "policy_verified": policy_path is not None,
            "warning": "Policy checks are not proof of anonymity or complete sensitive-data detection."}
