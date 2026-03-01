from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from ..models import AIBOM


def to_cyclonedx_json(aibom: AIBOM) -> Dict[str, Any]:
    """
    Serialize AIBOM to a minimal CycloneDX 1.7-compliant JSON structure.
    This is intentionally lightweight and can be extended later.
    """
    components = []
    for c in aibom.components:
        comp: Dict[str, Any] = {
            "type": c.type.value,
            "name": c.name,
        }
        if c.version:
            comp["version"] = c.version
        if c.purl:
            comp["purl"] = c.purl
        if c.licenses:
            comp["licenses"] = [{"license": {"name": lic}} for lic in c.licenses]
        if c.properties:
            comp["properties"] = [{"name": k, "value": str(v)} for k, v in c.properties.items()]
        components.append(comp)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "AITrace",
                    "name": "AITrace CLI",
                }
            ],
        },
        "components": components,
    }

