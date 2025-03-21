#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Analyzers module
Author: Marc Rivero | @seifreed
"""
import os
import re
import json
import concurrent.futures
import r2pipe
from config import CONFIG, get_output_path
from utils import is_pe_file, find_pe_files, BANNED_FUNCTIONS
from decompilers import check_decompiler_available, decompile_function

def analyze_function(r2, func, banned_functions, decompiler_type="default", verbose=False):
    """Analyzes a function for banned functions."""
    try:
        func_name = func.get("name", "")
        func_addr = func.get("offset", "")
        
        # Check if the function name contains any banned function
        detected_banned = []
        for banned_func in banned_functions:
            if banned_func.lower() in func_name.lower():
                detected_banned.append(banned_func)
        
        # If banned functions were already detected in the name, decompilation is not necessary
        if detected_banned:
            if verbose:
                print(f"[+] Insecure function detected by name: {func_name}")
            
            return {
                "name": func_name,
                "address": hex(func_addr),
                "banned_functions": detected_banned,
                "detection_method": "name"
            }
        
        # Decompile the function
        decompiled_code = decompile_function(r2, func_name, decompiler_type)
        
        # If decompilation failed, exit
        if not decompiled_code:
            return None
        
        # Search for banned functions in the decompiled code
        for banned_func in banned_functions:
            if banned_func.lower() in decompiled_code.lower():
                detected_banned.append(banned_func)
        
        # If banned functions were detected, return the result
        if detected_banned:
            if verbose:
                print(f"[+] Insecure function detected in decompiled code: {func_name}")
            
            return {
                "name": func_name,
                "address": hex(func_addr),
                "banned_functions": detected_banned,
                "detection_method": "decompilation",
                "decompiler": decompiler_type
            }
        
        return None
    except Exception as e:
        if verbose:
            print(f"[!] Error analyzing function {func.get('name', 'unknown')}: {str(e)}")
        return None

def analyze_binary(binary_path, output_dir=None, decompiler_type=None, verbose=False, worker_limit=None):
    """Analyzes a binary for banned functions."""
    if not os.path.exists(binary_path):
        print(f"[!] The file {binary_path} does not exist.")
        return None
    
    # Determine the decompiler type to use
    if decompiler_type is None:
        decompiler_type = CONFIG["decompiler"]["type"]
    
    # Check if the decompiler is available
    if not check_decompiler_available(decompiler_type):
        if verbose:
            print(f"[!] The decompiler {decompiler_type} is not available.")
            print("[!] Will try with the default decompiler.")
        
        # Try with the default decompiler
        decompiler_type = "default"
        if not check_decompiler_available(decompiler_type):
            if verbose:
                print("[!] Could not find an available decompiler.")
            return None
    
    # Determine the number of threads for r2pipe
    r2pipe_threads = CONFIG.get("r2pipe_threads", 10)
    
    # Open the binary with r2pipe
    try:
        # Configure r2pipe to use multiple threads if enabled
        if r2pipe_threads > 0:
            os.environ["R2PIPE_THREADS"] = str(r2pipe_threads)
        
        if verbose:
            print(f"[+] Opening {binary_path} with r2pipe...")
        
        r2 = r2pipe.open(binary_path, flags=["-2"])
        
        # Analyze the binary
        if verbose:
            print("[+] Analyzing the binary...")
        r2.cmd("aaa")
        
        # Get all functions
        if verbose:
            print("[+] Getting function list...")
        functions = r2.cmdj("aflj")
        
        if not functions:
            if verbose:
                print("[!] No functions found in the binary.")
            r2.quit()
            return None
        
        if verbose:
            print(f"[+] Found {len(functions)} functions.")
        
        # Check if the selected decompiler is available
        has_decompiler = check_decompiler_available(decompiler_type)
        
        if has_decompiler and verbose:
            print(f"[+] Using decompiler: {decompiler_type}")
        
        # Get the list of banned functions
        banned_functions = CONFIG.get("banned_functions", [])
        if not banned_functions:
            # If there are no banned functions in the configuration, use the default list
            banned_functions = list(BANNED_FUNCTIONS)
        
        # Results
        results = []
        
        # Limit the number of workers if specified
        if worker_limit is None:
            worker_limit = CONFIG.get("worker_limit", 10)
        
        # Create a worker pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=worker_limit) as executor:
            # Prepare tasks
            futures = []
            for func in functions:
                futures.append(executor.submit(
                    analyze_function, r2, func, banned_functions, decompiler_type, verbose
                ))
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        if verbose:
                            print(f"[+] Insecure function found: {result['name']} at {result['address']}")
                except Exception as e:
                    if verbose:
                        print(f"[!] Error analyzing a function: {str(e)}")
        
        # Close r2pipe
        r2.quit()
        
        # Save results if an output directory is specified
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f"{os.path.basename(binary_path)}_banned_functions.json")
            with open(output_file, 'w') as f:
                json.dump({
                    "binary": binary_path,
                    "total_functions": len(functions),
                    "unsafe_functions": len(results),
                    "results": results
                }, f, indent=4)
            
            if verbose:
                print(f"[+] Results saved to {output_file}")
        
        return {
            "binary": binary_path,
            "total_functions": len(functions),
            "unsafe_functions": len(results),
            "results": results
        }
    
    except Exception as e:
        print(f"[!] Error analyzing binary {binary_path}: {str(e)}")
        return None

def analyze_directory(directory, output_dir=None, decompiler_type=None, max_workers=None, verbose=False):
    """Analyzes all PE binaries in a directory for banned functions."""
    if not os.path.exists(directory):
        print(f"[!] The directory {directory} does not exist.")
        return None
    
    # Get the list of PE files in the directory
    pe_files = find_pe_files(directory)
    
    if not pe_files:
        print(f"[!] No PE files found in {directory}.")
        return None
    
    if verbose:
        print(f"[+] Found {len(pe_files)} PE files in {directory}.")
    
    # Determine the maximum number of workers
    if max_workers is None:
        max_workers = CONFIG.get("max_workers", 4)
    
    # Determine the decompiler type to use
    if decompiler_type is None:
        decompiler_type = CONFIG["decompiler"]["type"]
    
    # Create the output directory if it doesn't exist
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    # Results
    results = []
    
    # Analyze each PE file in parallel
    with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
        # Prepare tasks
        futures = {}
        for pe_file in pe_files:
            future = executor.submit(
                analyze_binary, 
                pe_file, 
                output_dir=output_dir,
                decompiler_type=decompiler_type,
                verbose=verbose,
                worker_limit=CONFIG.get("worker_limit", 10)
            )
            futures[future] = pe_file
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(futures):
            pe_file = futures[future]
            try:
                result = future.result()
                if result:
                    results.append(result)
                    if verbose:
                        print(f"[+] Analysis completed for {pe_file}.")
                        print(f"    Insecure functions found: {result['unsafe_functions']}")
            except Exception as e:
                if verbose:
                    print(f"[!] Error analyzing {pe_file}: {str(e)}")
    
    # Save a summary of the results
    if output_dir:
        summary_file = os.path.join(output_dir, "summary.json")
        with open(summary_file, 'w') as f:
            json.dump({
                "directory": directory,
                "total_files": len(pe_files),
                "analyzed_files": len(results),
                "results": results
            }, f, indent=4)
        
        if verbose:
            print(f"[+] Summary saved to {summary_file}")
    
    return {
        "directory": directory,
        "total_files": len(pe_files),
        "analyzed_files": len(results),
        "results": results
    } 