"""BannedFuncDetector - Domain Layer.

Core domain entities and types. For protocols and result types,
import directly from their respective modules:
    - domain.protocols: Interface definitions (IR2Client, IBinaryAnalyzer, etc.)
    - domain.result: Result monad (Result, Ok, Err, ok, err)
    - domain.types: TypedDicts and type aliases
    - domain.entities: Domain entities and constants
    - domain.config_types: Parameter objects for function signatures
"""

from .entities import BannedFunction, AnalysisResult
from .config_types import (
    AnalysisOptions,
    ParallelAnalysisOptions,
    DirectoryAnalysisOptions,
    BinaryAnalysisOptions,
)
from .banned_functions import (
    BANNED_FUNCTIONS,
    BANNED_FUNCTIONS_CATEGORIZED,
    get_category_for_function,
    get_banned_functions_set,
)

__all__ = [
    "BannedFunction",
    "AnalysisResult",
    "AnalysisOptions",
    "ParallelAnalysisOptions",
    "DirectoryAnalysisOptions",
    "BinaryAnalysisOptions",
    # Banned functions catalog
    "BANNED_FUNCTIONS",
    "BANNED_FUNCTIONS_CATEGORIZED",
    "get_category_for_function",
    "get_banned_functions_set",
]
