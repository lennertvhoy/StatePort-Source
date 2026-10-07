# template-validator

> Validates StateSpec templates and instances.

## Purpose

Ensures templates and instances conform to the StateSpec contract:

- Required files exist
- YAML parses correctly
- Required fields are present
- `kind` matches `Template` or `Instance`
- Allowed actions are well-defined
- Instance `templateRef` resolves to a valid template
- Instance `state/` files match the template's declared schemas

## Usage

```python
from template_validator import validate_template, validate_instance

result = validate_template("templates/classdd")
print(result.ok, result.issues)

result = validate_instance("instances/demo-classdd")
print(result.ok, result.issues)
```

## Status

Implemented in SP-001a.
