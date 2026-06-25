"""
BannedFuncDetector - File Detection Module

This module provides utilities for detecting and identifying executable files
across different platforms (Windows PE, Linux ELF, macOS Mach-O).

It uses python-magic library for reliable file type detection with fallback
to magic bytes analysis when needed.

Author: Marc Rivero | @seifreed
"""

import importlib
import logging
import os
from typing import Any

from ..constants import PE_MAGIC_BYTES_SIZE, PE_SIGNATURE


def _try_import_magic(module_name: str = "magic") -> Any | None:
    """Import the libmagic wrapper, returning ``None`` when it is unavailable.

    The module name is a parameter so the optional-dependency-missing branch
    can be exercised with a genuinely absent module, rather than monkeypatching
    the import machinery. A smoke ``from_file`` call also guards against the
    Windows access violations seen with some libmagic builds.
    """
    try:
        module = importlib.import_module(module_name)
        module.from_file(__file__)
        return module
    except Exception:
        return None


magic: Any | None = _try_import_magic()


def _load_magic_module() -> Any | None:
    """Load ``python-magic`` lazily to avoid hard failures when libmagic is absent."""
    if magic is not None:
        try:
            magic.from_file(__file__)
            return magic
        except Exception:
            return None
    return None


def is_magic_available() -> bool:
    """Whether python-magic/libmagic is usable for file-type detection.

    When False, detection falls back to magic-byte sniffing, which is less
    reliable for packed or obfuscated binaries.
    """
    return _load_magic_module() is not None


# Configure module logger
logger = logging.getLogger(__name__)

# =============================================================================
# FILE TYPE DETECTION
# =============================================================================

VALID_EXECUTABLE_TYPES = {"pe", "elf", "macho", "any"}


def _validate_executable_type(file_type: str) -> None:
    """Validate executable type input."""
    if file_type not in VALID_EXECUTABLE_TYPES:
        raise ValueError(
            f"Invalid file_type '{file_type}'. Must be one of: {VALID_EXECUTABLE_TYPES}"
        )


TYPE_MARKERS = {
    "pe": ("PE32", "PE32+"),
    "elf": ("ELF",),
    "macho": ("Mach-O",),
}
TYPE_LABELS = {
    "pe": "PE",
    "elf": "ELF",
    "macho": "Mach-O",
}

# Magic bytes for different executable formats
EXECUTABLE_MAGIC = {
    "pe": [PE_SIGNATURE],  # PE/DOS executable
    "elf": [b"\x7fELF"],  # ELF executable
    "macho": [
        b"\xfe\xed\xfa\xce",  # Mach-O 32-bit big endian
        b"\xce\xfa\xed\xfe",  # Mach-O 32-bit little endian
        b"\xfe\xed\xfa\xcf",  # Mach-O 64-bit big endian
        b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit little endian
        b"\xca\xfe\xba\xbe",  # Mach-O Universal binary big endian
        b"\xbe\xba\xfe\xca",  # Mach-O Universal binary little endian
    ],
}


def _detect_executable_with_magic(file_path: str, file_type: str) -> bool | None:
    """
    Detect executable type using python-magic library.

    Args:
        file_path: Path to the file to check.
        file_type: Type of executable to check for.

    Returns:
        True if libmagic confirms the requested type, otherwise None. None is
        returned both when magic is unavailable/errors AND when magic ran but
        did not confirm the type, so the caller always falls back to magic-byte
        sniffing — this is deliberate, so packed/obfuscated executables that
        libmagic reports as plain "data" are still caught by their header. It
        never returns False.
    """
    magic_module = _load_magic_module()
    if magic_module is None:
        return None

    try:
        detected_type = magic_module.from_file(file_path)
    except Exception as exc:
        logger.debug(
            "libmagic failed on %s, falling back to magic bytes: %s", file_path, exc
        )
        return None

    if file_type == "any":
        for exec_type, markers in TYPE_MARKERS.items():
            if any(marker in detected_type for marker in markers):
                logger.debug(
                    "Detected %s executable: %s", TYPE_LABELS[exec_type], file_path
                )
                return True
    else:
        if any(marker in detected_type for marker in TYPE_MARKERS[file_type]):
            logger.debug(
                "Detected %s executable: %s", TYPE_LABELS[file_type], file_path
            )
            return True

    return None


def is_executable_file(file_path: str, file_type: str = "pe") -> bool:
    """
    Check if a file is an executable of the specified type.

    This function uses python-magic library for reliable detection and falls
    back to checking magic bytes if needed.

    Args:
        file_path: Path to the file to check.
        file_type: Type of executable to check for. Valid values are:
                   - "pe": Windows PE executables (PE32, PE32+)
                   - "elf": Linux ELF executables
                   - "macho": macOS Mach-O executables
                   - "any": Any of the above executable types

    Returns:
        True if the file is an executable of the specified type, False otherwise.

    Raises:
        ValueError: If file_type is not a valid type.
    """
    _validate_executable_type(file_type)

    if not os.path.isfile(file_path):
        logger.debug("File does not exist: %s", file_path)
        return False

    try:
        result = _detect_executable_with_magic(file_path, file_type)
        if result is not None:
            return result
        return _check_magic_bytes(file_path, file_type)

    except (OSError, IOError) as e:
        logger.warning(
            "File access error for %s, falling back to magic bytes: %s",
            file_path,
            str(e),
        )
        return _check_magic_bytes(file_path, file_type)
    except (RuntimeError, ValueError, TypeError) as e:
        logger.warning(
            "Magic detection failed for %s, falling back to magic bytes: %s",
            file_path,
            str(e),
        )
        return _check_magic_bytes(file_path, file_type)


def _check_magic_bytes(file_path: str, file_type: str) -> bool:
    """
    Check file magic bytes to determine executable type.

    This is a fallback method when python-magic fails.

    Args:
        file_path: Path to the file to check.
        file_type: Type of executable to check for.

    Returns:
        True if magic bytes match the specified type, False otherwise.
    """
    try:
        with open(file_path, "rb") as f:
            # Read 8 bytes: sufficient for PE (2), ELF (4), and Mach-O (4) signature detection
            header = f.read(PE_MAGIC_BYTES_SIZE)

        # Expand "any" into all supported types for comprehensive checking
        types_to_check = ["pe", "elf", "macho"] if file_type == "any" else [file_type]

        for check_type in types_to_check:
            magic_bytes_list = EXECUTABLE_MAGIC.get(check_type, [])
            # Each type may have multiple valid signatures (e.g., Mach-O has 6 variants for endianness/architecture)
            for magic_bytes in magic_bytes_list:
                if header.startswith(magic_bytes):
                    logger.debug(
                        "Magic bytes match for %s type: %s", check_type, file_path
                    )
                    return True

        return False

    except (OSError, IOError) as e:
        # File access or read errors
        logger.error("Failed to read file %s: %s", file_path, str(e))
        return False
    except (ValueError, TypeError) as e:
        # Invalid data during processing
        logger.error("Data error checking file %s: %s", file_path, str(e))
        return False


# =============================================================================
# FILE DISCOVERY
# =============================================================================


def find_pe_files(directory: str) -> list[str]:
    """
    Find all PE executable files in a directory recursively.

    Args:
        directory: Path to the directory to search.

    Returns:
        List of paths to PE files found in the directory.

    Raises:
        ValueError: If directory does not exist or is not a directory.

    Examples:
        >>> pe_files = find_pe_files("/path/to/windows/binaries")
        >>> all(f.endswith(('.exe', '.dll')) for f in pe_files)
        True
    """
    return _find_executables(
        directory=directory,
        file_type="pe",
        debug_label="PE file",
        summary_label="PE files",
    )


def find_executable_files(directory: str, file_type: str = "any") -> list[str]:
    """
    Find all executable files of a specified type in a directory recursively.

    Args:
        directory: Path to the directory to search.
        file_type: Type of executable to search for ("pe", "elf", "macho", "any").

    Returns:
        List of paths to executable files found in the directory.

    Raises:
        ValueError: If directory does not exist or file_type is invalid.

    Examples:
        >>> elf_files = find_executable_files("/usr/bin", "elf")
        >>> len(elf_files) > 0
        True
        >>> all_execs = find_executable_files("/mixed/binaries", "any")
        >>> len(all_execs) >= len(elf_files)
        True
    """
    return _find_executables(
        directory=directory,
        file_type=file_type,
        debug_label=f"{file_type} executable",
        summary_label=f"{file_type} executables",
    )


def _log_walk_error(error: OSError) -> None:
    """Surface a directory-traversal failure so an incomplete scan is visible.

    os.walk swallows per-directory errors (e.g. an unreadable subdirectory)
    silently by default, which would let a scan skip part of the tree without
    any indication — dangerous when the tree holds samples to analyse.
    """
    logger.warning(
        "Cannot read %s during directory scan (%s); some files may be skipped.",
        getattr(error, "filename", None) or "a directory",
        error,
    )


def _find_executables(
    directory: str, file_type: str, debug_label: str, summary_label: str
) -> list[str]:
    """
    Find executable files of a specified type in a directory recursively.
    """
    if not os.path.isdir(directory):
        raise ValueError(f"Directory does not exist: {directory}")

    executable_files: list[str] = []
    visited_dirs: set[tuple[int, int]] = (
        set()
    )  # (device, inode) pairs for cycle detection

    for root, dirs, files in os.walk(
        directory, followlinks=True, onerror=_log_walk_error
    ):
        # Detect symlink cycles by tracking real directory identities
        real_root = os.path.realpath(root)
        try:
            stat = os.stat(real_root)
            dir_id = (stat.st_dev, stat.st_ino)
        except OSError:
            continue
        if dir_id in visited_dirs:
            logger.warning("Skipping circular symlink at: %s", root)
            dirs.clear()  # prevent os.walk from descending further
            continue
        visited_dirs.add(dir_id)

        for file in files:
            file_path = os.path.join(root, file)

            if os.path.islink(file_path):
                if not os.path.exists(file_path):
                    logger.warning("Skipping broken symlink: %s", file_path)
                    continue
                logger.debug("Following symlink: %s", file_path)

            if is_executable_file(file_path, file_type):
                executable_files.append(file_path)
                logger.debug("Found %s: %s", debug_label, file_path)

    logger.info("Found %d %s in %s", len(executable_files), summary_label, directory)
    return executable_files
