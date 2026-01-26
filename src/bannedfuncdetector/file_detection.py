#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - File Detection Module

This module provides utilities for detecting and identifying executable files
across different platforms (Windows PE, Linux ELF, macOS Mach-O).

It uses python-magic library for reliable file type detection with fallback
to magic bytes analysis when needed.

Author: Marc Rivero | @seifreed
"""

import logging
import os

import magic

from .constants import PE_MAGIC_BYTES_SIZE, PE_SIGNATURE

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
        True if executable detected, False if not detected, None if magic failed.
    """
    if magic is None:
        return None

    detected_type = magic.from_file(file_path)

    if file_type == "any":
        for exec_type, markers in TYPE_MARKERS.items():
            if any(marker in detected_type for marker in markers):
                logger.debug("Detected %s executable: %s", TYPE_LABELS[exec_type], file_path)
                return True
    else:
        if any(marker in detected_type for marker in TYPE_MARKERS[file_type]):
            logger.debug("Detected %s executable: %s", TYPE_LABELS[file_type], file_path)
            return True

    return False


def is_executable_file(
    file_path: str,
    file_type: str = "pe"
) -> bool:
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
            file_path, str(e)
        )
        return _check_magic_bytes(file_path, file_type)
    except (RuntimeError, ValueError, TypeError) as e:
        logger.warning(
            "Magic detection failed for %s, falling back to magic bytes: %s",
            file_path, str(e)
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
                        "Magic bytes match for %s type: %s",
                        check_type, file_path
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
        summary_label="PE files"
    )


def find_executable_files(
    directory: str,
    file_type: str = "any"
) -> list[str]:
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
        summary_label=f"{file_type} executables"
    )


def _find_executables(
    directory: str,
    file_type: str,
    debug_label: str,
    summary_label: str
) -> list[str]:
    """
    Find executable files of a specified type in a directory recursively.
    """
    if not os.path.isdir(directory):
        raise ValueError(f"Directory does not exist: {directory}")

    executable_files: list[str] = []

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)

            if is_executable_file(file_path, file_type):
                executable_files.append(file_path)
                logger.debug("Found %s: %s", debug_label, file_path)

    logger.info("Found %d %s in %s", len(executable_files), summary_label, directory)
    return executable_files


