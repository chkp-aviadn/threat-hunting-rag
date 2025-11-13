"""Pydantic compatibility helpers.

This module provides unified imports for Pydantic v2 while gracefully
degrading if a v1 environment is accidentally introduced. It lets the
codebase standardize on the new decorators (`field_validator`,
`model_validator`) without breaking if tools re-install an older
version temporarily.

Usage:
    from shared.pydantic_compat import BaseModel, Field, field_validator, model_validator

In v1 fallback mode:
    - `field_validator` maps to legacy `validator` (limited semantics)
    - `model_validator` becomes a no-op decorator (only preserves function)

In v2 mode (preferred):
    - Direct re-export of real decorators
"""

import sys
import types

try:
    from pydantic import BaseModel, Field  # Attempt normal import
except ImportError as e:
    # Handle missing Qualifier from typing_inspection in certain environments
    if "Qualifier" in str(e):
        # Create a stub typing_inspection.introspection module with Qualifier symbol
        introspection_mod = types.ModuleType("typing_inspection.introspection")

        class Qualifier:  # pragma: no cover - simple placeholder
            pass

        introspection_mod.Qualifier = Qualifier
        # Root package stub
        root_pkg = types.ModuleType("typing_inspection")
        root_pkg.__path__ = []  # type: ignore
        sys.modules["typing_inspection"] = root_pkg
        sys.modules["typing_inspection.introspection"] = introspection_mod
        from pydantic import BaseModel, Field  # Retry after stubbing
    else:
        raise

try:  # Pydantic v2 path
    from pydantic import field_validator, model_validator  # type: ignore

    PydanticV2 = True
except Exception:  # Fallback for unexpected v1 reinstallation
    from pydantic import validator as field_validator  # type: ignore

    def model_validator(*args, **kwargs):  # type: ignore
        """Fallback no-op for v1; returns original function unchanged."""

        def wrapper(fn):
            return fn

        return wrapper

    PydanticV2 = False

__all__ = [
    "BaseModel",
    "Field",
    "field_validator",
    "model_validator",
    "PydanticV2",
]
