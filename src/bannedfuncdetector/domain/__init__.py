"""BannedFuncDetector - Domain Layer.

Core domain entities. For protocols, runtime wiring, and result types,
import directly from their respective modules:
    - domain.protocols: Interface definitions (IR2Client, IBinaryAnalyzer, etc.)
    - domain.result: Result monad (Result, Ok, Err, ok, err)
    - domain.types: Type aliases for application-facing results
    - domain.entities: Domain entities and constants
    - application.contracts: Runtime wiring and public request objects
"""

from .entities import (
    FunctionDescriptor,
    BannedFunction,
    AnalysisResult,
    DirectoryAnalysisSummary,
)
from .banned_functions import (
    BANNED_FUNCTIONS,
    BANNED_FUNCTIONS_CATEGORIZED,
    get_category_for_function,
    get_banned_functions_set,
)

__all__ = [
    "FunctionDescriptor",
    "BannedFunction",
    "AnalysisResult",
    "DirectoryAnalysisSummary",
    # Banned functions catalog
    "BANNED_FUNCTIONS",
    "BANNED_FUNCTIONS_CATEGORIZED",
    "get_category_for_function",
    "get_banned_functions_set",
]
