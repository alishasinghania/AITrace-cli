from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from ..models import AIBOM


def to_spdx_json(aibom: AIBOM) -> Dict[str, Any]:
    """
    Serialize AIBOM to a minimal SPDX 3.0-style JSON document.
    This is not exhaustive but provides a useful baseline.
    """
    now = datetime.now(timezone.utc).isoformat()
    elements: List[Dict[str, Any]] = []

    for c in aibom.components:
        elem: Dict[str, Any] = {
            "type": "Package",
            "name": c.name,
        }
        if c.version:
            elem["versionInfo"] = c.version
        if c.licenses:
            elem["licenseDeclared"] = c.licenses[0]
        elements.append(elem)

    doc: Dict[str, Any] = {
        "spdxVersion": "SPDX-3.0",
        "creationInfo": {
            "created": now,
            "creators": ["Tool: AITrace CLI"],
        },
        "elements": elements,
    }
    return doc

