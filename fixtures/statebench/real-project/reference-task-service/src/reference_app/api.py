"""Visible API helper; this is intentionally not the complete feature."""


def normalize_title(value: str) -> str:
    return " ".join(value.split())
