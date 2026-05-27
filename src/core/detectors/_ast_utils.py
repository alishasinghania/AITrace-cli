"""
Shared AST utilities — backward compatibility re-export.
All implementations now live in core.utils.ast_utils.
"""
from __future__ import annotations

from ..utils.ast_utils import (  # noqa: F401
    should_skip_path,
    get_call_target,
    get_call_target_chain,
    get_call_chain,
    get_attr_chain,
    walk_python_files,
    scan_ast,
)

# Aliases for files that still import the underscore versions
_get_call_chain = get_call_chain
_get_attr_chain = get_attr_chain
_should_skip = should_skip_path
