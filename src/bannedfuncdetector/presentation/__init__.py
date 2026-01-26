"""BannedFuncDetector - Presentation Layer.

User interface components. Import directly from submodules:
    - presentation.reporting: Report generation (display_final_results, etc.)
    - cli: Argument parsing (parse_arguments)
"""

from .reporting import display_final_results

__all__ = [
    "display_final_results",
]
