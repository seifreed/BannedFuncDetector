#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLI module for BannedFuncDetector - Command line argument parsing.
Author: Marc Rivero | @seifreed
"""

import argparse


def parse_arguments() -> argparse.Namespace:
    """
    Parses command line arguments.

    Returns:
        argparse.Namespace: Object with parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description='BannedFuncDetector - Analyzes binaries to find banned functions. Author: Marc Rivero | @seifreed'
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help='Executable file to analyze')
    group.add_argument('-d', '--directory', help='Directory with executables to analyze')

    parser.add_argument('-o', '--output', default='output', help='Output directory for results')
    parser.add_argument('--decompiler', default='default', choices=['default', 'r2ghidra', 'r2dec', 'decai'],
                        help='Decompiler to use: default, r2ghidra, r2dec (traditional decompilers) or decai (AI assistant)')
    parser.add_argument('--force-decompiler', action='store_true', help='Force the use of the specified decompiler')
    parser.add_argument('--parallel', action='store_true', help='Process files in parallel (only with --directory)')
    parser.add_argument('--skip-banned', action='store_true', help='Skip the search for banned function names')
    parser.add_argument('--skip-analysis', action='store_true', help='Skip decompilation analysis')
    parser.add_argument('--check-requirements', action='store_true', help='Check system requirements before running')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed information during analysis')

    args = parser.parse_args()
    args.skip_requirements = not args.check_requirements

    return args
