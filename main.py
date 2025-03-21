#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Tool for detecting banned functions in binary files
Author: Marc Rivero | @seifreed
"""

import os
import argparse
import time
import subprocess
import requests
import sys
import json
import traceback
from config import CONFIG, load_config, ensure_output_dir_exists
from utils import check_r2ai_server_available
from decompilers import check_decompiler_available
from analyzers import analyze_binary, analyze_directory
import r2pipe
import datetime
import multiprocessing
import functools
import decompilers
import detector

def check_requirements(skip_requirements=True):
    """
    Verifies that all requirements to run the tool are met.
    
    Args:
        skip_requirements: If True, skips the requirements check.
        
    Returns:
        bool: True if all requirements are met, False otherwise.
    """
    if skip_requirements:
        return True
    
    # List of requirements
    requirements = [
        {"name": "r2", "command": "r2 -v", "expected": "radare2"},
        {"name": "r2pipe", "command": "python -c \"import r2pipe; print('r2pipe installed')\"", "expected": "r2pipe installed"}
    ]
    
    all_requirements_met = True
    
    for req in requirements:
        try:
            print(f"[*] Checking {req['name']}...")
            result = subprocess.run(req['command'], shell=True, capture_output=True, text=True)
            
            if result.returncode != 0 or req['expected'] not in result.stdout:
                print(f"[!] Error: {req['name']} is not installed or not working properly.")
                print(f"[!] Output: {result.stdout}")
                if result.stderr:
                    print(f"[!] Error: {result.stderr}")
                all_requirements_met = False
            else:
                print(f"[+] {req['name']} is installed correctly.")
        except Exception as e:
            print(f"[!] Error checking {req['name']}: {str(e)}")
            all_requirements_met = False
    
    # Check availability of decompilers
    try:
        import decompilers
        print("[*] Checking available decompilers...")
        
        # Create an r2pipe instance to check decompilers
        temp_binary = "/bin/ls"  # Use a known binary for checking
        if os.path.exists(temp_binary):
            try:
                r2 = r2pipe.open(temp_binary)
                
                decompiler_types = ["default", "r2ghidra", "r2dec", "decai"]
                available_decompilers = []
                
                # First pass to check without printing messages
                for decompiler in decompiler_types:
                    if decompilers.check_decompiler_available(decompiler, print_message=False):
                        available_decompilers.append(decompiler)
                
                # Show results in a single block
                for decompiler in available_decompilers:
                    print(f"[+] Decompiler {decompiler} is available.")
                
                for decompiler in [d for d in decompiler_types if d not in available_decompilers]:
                    print(f"[!] Decompiler {decompiler} is not available.")
                
                r2.quit()
                
                if not available_decompilers:
                    print("[!] Warning: No decompilers found.")
                    print("[!] Analysis will be limited to searching for banned functions by name.")
                    # Don't fail if no decompilers are available, just warn
                
            except Exception as e:
                print(f"[!] Error checking decompilers: {str(e)}")
                # Don't fail if there's an error checking decompilers, just warn
        else:
            print(f"[!] Could not find a binary to check decompilers: {temp_binary}")
            # Don't fail if we can't check decompilers, just warn
            
    except ImportError:
        print("[!] Could not import decompilers module to check decompilers.")
        # Don't fail if we can't import decompilers, just warn
    
    return all_requirements_met

def parse_arguments():
    """
    Parses command line arguments.
    
    Returns:
        argparse.Namespace: Object with parsed arguments.
    """
    parser = argparse.ArgumentParser(description='BannedFuncDetector - Analyzes binaries to find banned functions. Author: Marc Rivero | @seifreed')
    
    # Exclusive group: file or directory
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help='Executable file to analyze')
    group.add_argument('-d', '--directory', help='Directory with executables to analyze')
    
    # Optional arguments
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
    
    # Convert --check-requirements to skip_requirements (inverted)
    args.skip_requirements = not args.check_requirements
    
    return args

def analyze_file(file_path, output_dir='output', decompiler_type='default', json_output=None, verbose=False, 
                skip_banned=False, skip_analysis=False, summary=False, force_decompiler=False, custom_model=None):
    """
    Analyzes an executable file for unsafe functions.
    
    Args:
        file_path: Path to the executable file.
        output_dir: Directory where results will be saved.
        decompiler_type: Type of decompiler to use.
        json_output: JSON file to save the results.
        verbose: If True, shows detailed information during analysis.
        skip_banned: If True, skips the search for banned functions by name.
        skip_analysis: If True, skips code analysis.
        summary: If True, shows only a summary of the results.
        force_decompiler: If True, forces the use of the specified decompiler without asking for alternatives.
        custom_model: Custom model for AI decompilers.
    
    Returns:
        dict: Analysis results.
    """
    # Check if the file exists
    if not os.path.exists(file_path):
        print(f"[!] File {file_path} does not exist.")
        return None
    
    # Check if the file is a PE/COFF binary
    if not is_binary_file(file_path):
        print(f"[!] File {file_path} is not a valid binary.")
        return None
    
    # Create output directory if it doesn't exist
    file_name = os.path.basename(file_path)
    output_path = os.path.join(output_dir, file_name)
    os.makedirs(output_path, exist_ok=True)
    
    # If r2ai is requested, change to default since r2ai is not a decompiler
    if decompiler_type == "r2ai":
        print("[!] r2ai is not a decompiler. Changing to default decompiler.")
        decompiler_type = "default"
    
    # Determine and verify the decompiler to use
    if not force_decompiler and not check_decompiler_available(decompiler_type):
        print(f"[!] Decompiler {decompiler_type} is not available.")
        print("[*] Checking available alternatives...")
        
        # Automatically select an available alternative
        alternatives = []
        
        # Decide which alternatives to try based on the requested decompiler
        if decompiler_type in ["decai"]:
            # If an AI assistant is not available, prefer traditional decompilers
            alternatives = ["r2ghidra", "r2dec", "default"]
        else:
            # For traditional decompilers, prefer other traditional ones first
            alternatives = ["r2ghidra", "r2dec", "default"]
        
        # Check each alternative
        for alt in alternatives:
            if check_decompiler_available(alt, print_message=False):
                if alt == "decai":
                    print(f"[+] AI assistant plugin '{alt}' is available as an alternative.")
                else:
                    print(f"[+] Decompiler '{alt}' is available as an alternative.")
                print(f"[+] Using '{alt}' automatically.")
                decompiler_type = alt
                break
        else:
            print("[*] No alternatives available. Using default decompiler.")
            decompiler_type = "default"

    # Start analysis
    try:
        # Open the file with r2pipe
        r2 = r2pipe.open(file_path)
        
        # Perform full analysis
        print("[+] Getting function list...")
        r2.cmd("aaa")
        
        # Get function list
        functions = r2.cmdj("aflj")
        if not functions:
            print("[!] No functions found in the file.")
            r2.quit()
            return None
        
        print(f"[+] Found {len(functions)} functions.")
        
        # Search for banned functions by name
        banned_functions = []
        if not skip_banned:
            banned_functions = detector.get_banned_functions_by_name(r2, functions)
        
        # Perform code analysis with the selected decompiler
        detected_functions = []
        if not skip_analysis:
            detected_functions = decompilers.decompile_with_selected_decompiler(
                r2, functions, banned_functions, decompiler_type=decompiler_type, verbose=verbose
            )
        
        # Combine results
        all_detected = banned_functions + detected_functions
        
        # Remove duplicates by address
        unique_detected = []
        addresses = set()
        for func in all_detected:
            if func['address'] not in addresses:
                unique_detected.append(func)
                addresses.add(func['address'])
        
        # Generate report
        report = {
            'file_name': file_name,
            'file_path': file_path,
            'analysis_date': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'analyzer': 'BannedFuncDetector - Author: Marc Rivero | @seifreed',
            'total_functions': len(functions),
            'insecure_functions': len(unique_detected),
            'insecure_functions_details': unique_detected
        }
        
        # Save results to a JSON file
        json_file = json_output if json_output else os.path.join(output_path, f"{file_name}_banned_functions.json")
        with open(json_file, 'w') as f:
            json.dump(report, f, indent=4)
        
        print(f"\n[+] Results saved to {json_file}")
        
        # Close r2pipe
        r2.quit()
        
        # Show summary
        print("\n[+] Analysis completed.")
        print(f"[+] Total functions analyzed: {len(functions)}")
        print(f"[+] Insecure functions found: {len(unique_detected)}")
        
        if not summary and unique_detected:
            print("\n[!] Detected insecure functions:")
            for func in unique_detected:
                print(f"  - {func['name']} at {hex(func['address'])}")
                if 'banned_functions' in func:
                    print(f"    Banned functions: {', '.join(func['banned_functions'])}")
        
        print(f"\n[+] Results saved to: {output_path}")
        
        return report
    
    except Exception as e:
        print(f"[!] Error during analysis: {str(e)}")
        traceback.print_exc()
        return None

def main():
    """
    Main program function.
    """
    # Step 1: Parse arguments
    args = parse_arguments()
    
    # Step 2: Check system requirements (optional)
    if not args.skip_requirements:
        print("[*] Checking system requirements...")
        if not check_requirements(False):  # Pass False because we want to do the actual check
            print("[!] Not all system requirements are met.")
            sys.exit(1)
        print("[*] Requirements check completed.")
    else:
        # Skip silently, no longer showing message indicating it was skipped
        pass
    
    # Step 3: Load configuration
    load_config()
    
    # Step 4: Create output directory if it doesn't exist
    os.makedirs(args.output, exist_ok=True)
    
    # Step 5: Process file or directory as appropriate
    if args.file:
        # Analyze a single file
        result = analyze_file(
            args.file, 
            args.output, 
            args.decompiler, 
            verbose=args.verbose,
            force_decompiler=args.force_decompiler,
            skip_banned=args.skip_banned,
            skip_analysis=args.skip_analysis
        )
    else:
        # Analyze all files in the directory
        if args.parallel:
            result = analyze_directory_parallel(
                args.directory, 
                args.output, 
                args.decompiler,
                verbose=args.verbose,
                force_decompiler=args.force_decompiler,
                skip_banned=args.skip_banned,
                skip_analysis=args.skip_analysis
            )
        else:
            result = analyze_directory(
                args.directory, 
                args.output, 
                args.decompiler,
                verbose=args.verbose,
                force_decompiler=args.force_decompiler,
                skip_banned=args.skip_banned,
                skip_analysis=args.skip_analysis
            )
    
    # Step 6: Show results
    if result:
        print("\n[+] Analysis completed.")
        total_files = len(result) if isinstance(result, list) else 1
        
        # Correct the count of insecure functions
        if isinstance(result, list):
            total_banned = sum(len(r.get("insecure_functions_details", [])) for r in result)
        else:
            total_banned = len(result.get("insecure_functions_details", []))
        
        print(f"[+] Total files analyzed: {total_files}")
        print(f"[+] Insecure functions found: {total_banned}")
        
        if total_banned > 0:
            print("\n[!] Detected insecure functions:")
            if isinstance(result, list):
                for file_result in result:
                    for func in file_result.get("insecure_functions_details", []):
                        print(f"  - {func['name']} at {hex(func['address'])}")
                        if 'banned_functions' in func:
                            print(f"    Banned functions: {', '.join(func['banned_functions'])}")
            else:
                for func in result.get("insecure_functions_details", []):
                    print(f"  - {func['name']} at {hex(func['address'])}")
                    if 'banned_functions' in func:
                        print(f"    Banned functions: {', '.join(func['banned_functions'])}")
    else:
        print("\n[!] No results found or errors occurred during analysis.")
    
    return 0

def analyze_directory_parallel(directory, output_dir='output', decompiler_type='default', num_threads=None, 
                              verbose=False, skip_banned=False, skip_analysis=False, summary=False, 
                              force_decompiler=False, custom_model=None):
    """
    Analyzes all executable files in a directory in parallel.
    
    Args:
        directory: Path to the directory with executables.
        output_dir: Directory where results will be saved.
        decompiler_type: Type of decompiler to use.
        num_threads: Number of threads for parallel analysis.
        verbose: If True, shows detailed information during analysis.
        skip_banned: If True, skips the search for banned functions by name.
        skip_analysis: If True, skips code analysis.
        summary: If True, shows only a summary of the results.
        force_decompiler: If True, forces the use of the specified decompiler without asking for alternatives.
        custom_model: Custom model for AI decompilers.
    
    Returns:
        list: List of analysis results.
    """
    # Check if the directory exists
    if not os.path.exists(directory) or not os.path.isdir(directory):
        print(f"[!] Directory {directory} does not exist.")
        return None
    
    # Get list of executable files
    executable_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if is_binary_file(file_path):
                executable_files.append(file_path)
    
    if not executable_files:
        print(f"[!] No executable files found in {directory}.")
        return None
    
    print(f"[+] Found {len(executable_files)} executable files.")
    
    # Determine number of threads
    if not num_threads:
        num_threads = min(os.cpu_count(), len(executable_files))
    
    print(f"[+] Starting parallel analysis with {num_threads} threads...")
    
    # Create process pool
    with multiprocessing.Pool(processes=num_threads) as pool:
        analyze_func = functools.partial(
            analyze_file,
            output_dir=output_dir,
            decompiler_type=decompiler_type,
            verbose=verbose,
            skip_banned=skip_banned,
            skip_analysis=skip_analysis,
            summary=summary,
            force_decompiler=force_decompiler,
            custom_model=custom_model
        )
        
        # Run analysis in parallel
        results = pool.map(analyze_func, executable_files)
    
    # Filter None results
    valid_results = [result for result in results if result]
    
    print(f"[+] Analysis completed. Analyzed {len(valid_results)} of {len(executable_files)} files.")
    
    return valid_results

def analyze_directory(directory, output_dir='output', decompiler_type='default', verbose=False, 
                     skip_banned=False, skip_analysis=False, summary=False, 
                     force_decompiler=False, custom_model=None):
    """
    Analyzes all executable files in a directory sequentially.
    
    Args:
        directory: Path to the directory with executables.
        output_dir: Directory where results will be saved.
        decompiler_type: Type of decompiler to use.
        verbose: If True, shows detailed information during analysis.
        skip_banned: If True, skips the search for banned functions by name.
        skip_analysis: If True, skips code analysis.
        summary: If True, shows only a summary of the results.
        force_decompiler: If True, forces the use of the specified decompiler without asking for alternatives.
        custom_model: Custom model for AI decompilers.
    
    Returns:
        list: List of analysis results.
    """
    # Check if the directory exists
    if not os.path.exists(directory) or not os.path.isdir(directory):
        print(f"[!] Directory {directory} does not exist.")
        return None
    
    # Get list of executable files
    executable_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if is_binary_file(file_path):
                executable_files.append(file_path)
    
    if not executable_files:
        print(f"[!] No executable files found in {directory}.")
        return None
    
    print(f"[+] Found {len(executable_files)} executable files.")
    
    # Analyze each file sequentially
    results = []
    for file_path in executable_files:
        print(f"\n[*] Analyzing {file_path}...")
        result = analyze_file(
            file_path, 
            output_dir=output_dir, 
            decompiler_type=decompiler_type,
            verbose=verbose,
            skip_banned=skip_banned,
            skip_analysis=skip_analysis,
            summary=summary,
            force_decompiler=force_decompiler,
            custom_model=custom_model
        )
        
        if result:
            results.append(result)
    
    print(f"[+] Analysis completed. Analyzed {len(results)} of {len(executable_files)} files.")
    
    return results

def is_binary_file(file_path):
    """Checks if a file is an executable binary."""
    try:
        import magic
        file_type = magic.from_file(file_path, mime=True)
        
        # Check if it's an executable
        if "application/x-executable" in file_type or "application/x-dosexec" in file_type:
            return True
        
        # In case magic doesn't detect correctly, check common extensions
        extensions = ['.exe', '.dll', '.so', '.dylib', '.bin', '.sys']
        if any(file_path.lower().endswith(ext) for ext in extensions):
            return True
        
        return False
    except Exception as e:
        print(f"[!] Error checking file type {file_path}: {str(e)}")
        # In case of error, try with os.access to check execution permissions
        return os.path.isfile(file_path) and os.access(file_path, os.X_OK)

if __name__ == "__main__":
    main() 