# statedd-core

> Core types and schemas for StateSpec, retaining StateDD package identifiers for compatibility.

## Purpose

Defines the data structures shared across StatePort:

- Template contract dataclasses (`Template`, `TemplateSpec`, `TemplateMetadata`, ...)
- Instance configuration dataclasses (`Instance`, `InstanceSpec`, `InstanceMetadata`, ...)
- Action, quota, approval, and GDPR types
- Shared legacy-compatible `StateDDError` exception hierarchy
- Stdlib-only YAML parser for the StateSpec YAML style
- Versioned template source descriptors, ownership-aware override reports, and
  read-only upgrade plans
- A strict, non-authoritative canonical-source catalog that separates verified
  releases from immutable development candidates before exact source resolution
- Source-linked StateIR normalization from manifest-owned YAML/Markdown
- Disposable StatePack compilation with explicit profile, selection, budget,
  provenance, staleness, truncation, and token-measurement metadata

## Usage

```python
from statedd_core import Template, Instance
from statedd_core.yaml import parse_yaml_text

template = Template.from_dict(parse_yaml_text(template_yaml_text))
instance = Instance.from_dict(parse_yaml_text(instance_yaml_text))
```

## Status

The lifecycle API supports deterministic local materialisation and lockfiles,
source identity independent of checkout path, explicit override
classification, and non-mutating upgrade planning. Automatic upgrade apply is
intentionally not part of this package.

Canonical application metadata is upstream of that lifecycle authority:

```python
from statedd_core import load_canonical_source_descriptor

source = load_canonical_source_descriptor("sources/canonical/studydd.yaml")
assert source.identity is None
assert source.status.installable is False
assert source.development_candidate is not None
```

The candidate's exact commit, tree, manifest digest, and source digest are an
observation for explicit development testing only. A production installation
requires a separately verified immutable release tag, successful resolution
through `SourceContract`, required modules and self-tests, and the existing
lifecycle plan, approval, transaction, lock, and receipt.

Context compilation is read-only and derived:

```python
from statedd_core import build_state_ir, build_state_pack

ir = build_state_ir("instances/my-instance")
pack = build_state_pack(
    ir,
    task="prepare the next lesson",
    model="configured-model",
    budget_tokens=2000,
    profile="compact",
    selection="eager",
)
```

Canonical YAML and Markdown remain authoritative. The default whitespace token
counter is labelled approximate; pass a configured model tokenizer callback and
`tokenizer_id` when exact model-specific measurement is available.
