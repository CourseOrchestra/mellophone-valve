from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any, Dict


def normalize_key(key: str) -> str:
    """Normalize XML key by removing @ prefix."""

    return key.lstrip("@")


def merge_value(target: Dict[str, Any], key: str, value: Any) -> None:
    """Merge duplicate XML keys into list while preserving existing value."""

    if key not in target:
        target[key] = value
        return
    current = target[key]
    if isinstance(current, list):
        current.append(value)
        return
    target[key] = [current, value]


def element_to_dict(element: ET.Element) -> Any:
    """Recursively convert XML element to native Python structure."""

    value: Dict[str, Any] = {}

    for attr_key, attr_value in element.attrib.items():
        value[normalize_key(attr_key)] = attr_value

    children = list(element)
    if children:
        for child in children:
            child_value = element_to_dict(child)
            merge_value(value, normalize_key(child.tag), child_value)
        text = (element.text or "").strip()
        if text:
            value["text"] = text
        return value

    text = (element.text or "").strip()
    if value:
        if text:
            value["text"] = text
        return value
    return text


def xml_to_json(xml: str) -> Dict[str, Any]:
    """Parse XML string and return normalized root object."""

    root = ET.fromstring(xml)
    return {normalize_key(root.tag): element_to_dict(root)}


def user_to_xml(user: Dict[str, Any]) -> str:
    """Serialize user dict into Mellophone API XML payload."""

    root = ET.Element("user")
    for key, value in user.items():
        root.set(normalize_key(key), str(value))
    return ET.tostring(root, encoding="unicode")


__all__ = [
    "normalize_key",
    "merge_value",
    "element_to_dict",
    "xml_to_json",
    "user_to_xml",
]
