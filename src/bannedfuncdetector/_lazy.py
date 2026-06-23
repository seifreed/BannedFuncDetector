"""Shared lazy-export resolver for package ``__init__`` modules.

Every layer's ``__init__`` keeps its public surface importable without eagerly
pulling in the full runtime stack. They all need the exact same ``__getattr__``
body, so it lives here once instead of being copied per package.
"""

from collections.abc import Callable
from importlib import import_module
from typing import Any


def lazy_exports(
    module_name: str,
    exports: dict[str, tuple[str, str]],
    namespace: dict[str, Any],
) -> Callable[[str], Any]:
    """Build a module ``__getattr__`` that resolves ``exports`` lazily.

    ``exports`` maps each public name to a ``(module, attribute)`` pair. On first
    access the target module is imported, the attribute fetched and cached into
    ``namespace`` so subsequent lookups bypass ``__getattr__`` entirely.
    """

    def __getattr__(name: str) -> Any:
        if name not in exports:
            raise AttributeError(f"module {module_name!r} has no attribute {name!r}")
        target_module, attribute = exports[name]
        value = getattr(import_module(target_module), attribute)
        namespace[name] = value
        return value

    return __getattr__
