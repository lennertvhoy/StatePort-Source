"""Stdlib-only YAML parser for the StateDD YAML style."""

from __future__ import annotations

import re
from typing import Any

from statedd_core.exceptions import StateDDError


class StateDDYamlError(StateDDError):
    pass


def strip_inline_comment(value: str) -> str:
    in_quote: str | None = None
    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char in {"'", '"'}:
            if in_quote == char:
                in_quote = None
            elif in_quote is None:
                in_quote = char
            continue
        if char == "#" and in_quote is None and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip()
    return value.rstrip()


def scalar(value: str) -> Any:
    value = strip_inline_comment(value.strip())
    if value == "":
        return ""
    if value in {"[]", "[ ]"}:
        return []
    if value in {"{}", "{ }"}:
        return {}
    if value.lower() == "null":
        return None
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    if re.fullmatch(r"-?\d+", value):
        try:
            return int(value)
        except ValueError:
            pass
    # Reject non-standard scalar forms that YAML users might expect.
    if re.fullmatch(r"[+-]?\d+\.\d*|\.\d+|[+-]?\.\d+", value):
        raise StateDDYamlError(f"unsupported float scalar: {value!r}; quote the value if it is intended as a string")
    if value.startswith("+") and re.fullmatch(r"\+\d+", value):
        raise StateDDYamlError(f"unsupported positive-sign integer: {value!r}; quote the value if it is intended as a string")
    if value.lower() in {"yes", "no", "on", "off", "y", "n"}:
        raise StateDDYamlError(f"unsupported boolean scalar: {value!r}; quote the value if it is intended as a string")
    if value.lower() in {".inf", "-.inf", "+.inf", ".nan", "nan", "~"}:
        raise StateDDYamlError(f"unsupported special scalar: {value!r}; quote the value if it is intended as a string")
    return value


def preprocess_yaml(text: str) -> list[tuple[int, str, int]]:
    lines: list[tuple[int, str, int]] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if stripped.startswith("#"):
            continue
        if stripped == "":
            # Preserve blank lines so block scalars retain paragraph breaks.
            lines.append((len(raw) - len(raw.lstrip(" ")), "", lineno))
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if "\t" in raw[:indent]:
            raise StateDDYamlError(f"line {lineno}: tabs are not supported in indentation")
        lines.append((indent, raw[indent:].rstrip(), lineno))
    return lines


def parse_yaml_text(text: str, max_depth: int = 100) -> Any:
    lines = preprocess_yaml(text)
    if not lines:
        return {}
    value, index = parse_block(lines, 0, lines[0][0], max_depth)
    if index != len(lines):
        _, content, lineno = lines[index]
        raise StateDDYamlError(f"line {lineno}: unexpected content after YAML block: {content}")
    return value


def parse_block(lines: list[tuple[int, str, int]], index: int, indent: int, max_depth: int) -> tuple[Any, int]:
    if max_depth <= 0:
        raise StateDDYamlError("YAML document exceeds maximum nesting depth")
    if index >= len(lines):
        return {}, index
    current_indent, content, _ = lines[index]
    if current_indent < indent:
        return {}, index
    if content.startswith("- "):
        return parse_sequence(lines, index, current_indent, max_depth)
    return parse_mapping(lines, index, current_indent, max_depth)


def parse_sequence(lines: list[tuple[int, str, int]], index: int, indent: int, max_depth: int) -> tuple[list[Any], int]:
    items: list[Any] = []
    while index < len(lines):
        current_indent, content, lineno = lines[index]
        if content == "":
            index += 1
            continue
        if current_indent < indent:
            break
        if current_indent != indent or not content.startswith("- "):
            break
        item_text = content[2:].strip()
        index += 1
        if item_text == "":
            if index < len(lines) and lines[index][0] > indent:
                item, index = parse_block(lines, index, lines[index][0], max_depth - 1)
            else:
                item = None
            items.append(item)
            continue
        if re.match(r"^[A-Za-z0-9_.-]+:\s*", item_text):
            key, value_text = split_key_value(item_text, lineno)
            item_map: dict[str, Any] = {}
            if value_text in {"|", ">"}:
                item_map[key], index = parse_block_scalar(lines, index, indent + 2, value_text == ">")
            elif value_text == "":
                if index < len(lines) and lines[index][0] > indent:
                    item_map[key], index = parse_block(lines, index, lines[index][0], max_depth - 1)
                else:
                    item_map[key] = {}
            else:
                item_map[key] = scalar(value_text)
            if index < len(lines) and lines[index][0] > indent:
                extra, index = parse_mapping(lines, index, lines[index][0], max_depth - 1)
                for extra_key, extra_value in extra.items():
                    if extra_key in item_map:
                        raise StateDDYamlError(f"line {lines[index - 1][2]}: duplicate mapping key: {extra_key}")
                    item_map[extra_key] = extra_value
            items.append(item_map)
        else:
            items.append(scalar(item_text))
    return items, index


def split_key_value(content: str, lineno: int) -> tuple[str, str]:
    if ":" not in content:
        raise StateDDYamlError(f"line {lineno}: expected key: value")
    key, value = content.split(":", 1)
    key = key.strip()
    if not key:
        raise StateDDYamlError(f"line {lineno}: empty mapping key")
    return key, value.strip()


def parse_mapping(lines: list[tuple[int, str, int]], index: int, indent: int, max_depth: int) -> tuple[dict[str, Any], int]:
    mapping: dict[str, Any] = {}
    while index < len(lines):
        current_indent, content, lineno = lines[index]
        if content == "":
            index += 1
            continue
        if current_indent < indent:
            break
        if current_indent != indent or content.startswith("- "):
            break
        key, value_text = split_key_value(content, lineno)
        if key in mapping:
            raise StateDDYamlError(f"line {lineno}: duplicate mapping key: {key}")
        index += 1
        if value_text in {"|", ">"}:
            mapping[key], index = parse_block_scalar(lines, index, indent + 2, value_text == ">")
        elif value_text == "":
            if index < len(lines) and lines[index][0] > indent:
                mapping[key], index = parse_block(lines, index, lines[index][0], max_depth - 1)
            else:
                mapping[key] = {}
        else:
            mapping[key] = scalar(value_text)
    return mapping, index


def parse_block_scalar(lines: list[tuple[int, str, int]], index: int, min_indent: int, folded: bool = False) -> tuple[str, int]:
    parts: list[str] = []
    block_indent: int | None = None
    while index < len(lines):
        indent, content, _ = lines[index]
        if content != "" and indent < min_indent:
            break
        if block_indent is None and content != "":
            block_indent = indent
        dedent = max(indent - (block_indent or indent), 0)
        parts.append(" " * dedent + content)
        index += 1
    if folded:
        return _format_folded(parts), index
    return "\n".join(parts), index


def _format_folded(lines: list[str]) -> str:
    """Join consecutive non-blank lines with a single space; keep blank lines as paragraph breaks."""
    paragraphs: list[str] = []
    current: list[str] = []
    for line in lines:
        if line == "":
            if current:
                paragraphs.append(" ".join(current))
                current = []
            paragraphs.append("")
        else:
            current.append(line)
    if current:
        paragraphs.append(" ".join(current))
    return "\n".join(paragraphs)
