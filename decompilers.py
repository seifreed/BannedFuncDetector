#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Decompilers module
Author: Marc Rivero | @seifreed
"""

import os
import re
import subprocess
import requests
import time
import r2pipe
from config import CONFIG
from utils import check_r2ai_server_available
import tempfile
import json
from detector import INSECURE_FUNCTIONS

def check_decompiler_available(decompiler_type, print_message=True):
    """
    Checks if a decompiler is available on the system.
    
    Args:
        decompiler_type: Type of decompiler (r2ghidra, r2dec, decai, etc.).
        print_message: If True, prints availability messages.
        
    Returns:
        bool: True if the decompiler is available, False otherwise.
    """
    try:
        if decompiler_type == "r2ghidra":
            # Check that r2ghidra is installed
            r2 = r2pipe.open("-")
            result = r2.cmd("Lc")
            r2.quit()
            is_available = "r2ghidra" in result
            if print_message:
                if is_available:
                    print(f"[+] Decompiler {decompiler_type} is available")
                else:
                    print(f"[!] Decompiler {decompiler_type} is not available")
            return is_available
            
        elif decompiler_type == "r2dec":
            # Check that r2dec is installed
            r2 = r2pipe.open("-")
            result = r2.cmd("Lc")
            r2.quit()
            is_available = "pdd" in result or "r2dec" in result
            if print_message:
                if is_available:
                    print(f"[+] Decompiler {decompiler_type} is available")
                else:
                    print(f"[!] Decompiler {decompiler_type} is not available")
            return is_available
            
        elif decompiler_type == "r2ai":
            # r2ai is not a decompiler, it's an AI assistant
            if print_message:
                print(f"[!] r2ai is not a decompiler, it's an AI assistant. Please use a decompiler like r2ghidra or r2dec")
            return False
            
        elif decompiler_type == "decai":
            try:
                # Check that decai is installed
                r2 = r2pipe.open("-")
                result = r2.cmd("decai -h")
                r2.quit()
                is_available = "Usage: decai" in result and "Unknown command" not in result
                
                # Check that ollama is running
                if is_available:
                    try:
                        # Check if Ollama is available
                        response = requests.get("http://localhost:11434/api/tags", timeout=1)
                        if response.status_code == 200:
                            if print_message:
                                print(f"[+] Plugin decai (AI-based assistant, not a decompiler) is available and Ollama is running")
                            return True
                        else:
                            if print_message:
                                print(f"[!] Plugin decai is available but Ollama is not responding")
                            return False
                    except Exception:
                        if print_message:
                            print(f"[!] Plugin decai is available but cannot connect to Ollama")
                        return False
                else:
                    if print_message:
                        print(f"[!] Plugin decai is not available")
                    return False
            except Exception as e:
                if print_message:
                    print(f"[!] Error checking decompiler {decompiler_type}: {str(e)}")
                return False
                
        elif decompiler_type == "default":
            # The default decompiler is always available
            if print_message:
                print(f"[+] Default decompiler is available")
            return True
            
        else:
            if print_message:
                print(f"[!] Unknown decompiler type: {decompiler_type}")
            return False
            
    except Exception as e:
        if print_message:
            print(f"[!] Error checking decompiler {decompiler_type}: {str(e)}")
        return False

def decompile_with_decai(r2, function_name):
    """
    Decompiles a function using the decai plugin from radare2.
    
    Args:
        r2: r2pipe instance.
        function_name: Name of the function to decompile.
        
    Returns:
        str: Decompiled code or error message.
    """
    try:
        # Check if the function exists
        function_info = get_function_info(r2, function_name)
        if not function_info:
            return f"Could not get function information: {function_name}"
        
        # Make sure function_info is a dictionary
        # If it's a list, take the first element
        if isinstance(function_info, list):
            if len(function_info) > 0:
                function_info = function_info[0]
            else:
                return f"Could not get valid function information: {function_name}"
        
        # Validate that function_info has the 'offset' key
        if not isinstance(function_info, dict) or 'offset' not in function_info:
            # Try to use the function name directly as an address
            r2.cmd(f"s {function_name}")
            # Check if we could move to a valid address
            addr_info = r2.cmdj("sj")
            if not addr_info or not isinstance(addr_info, dict) or 'offset' not in addr_info:
                return f"Could not get valid function information: {function_name}"
            function_offset = addr_info['offset']
        else:
            function_offset = function_info['offset']
            
        # Check if the decai plugin is available
        decai_check = r2.cmd("decai -h")
        if "Unknown command" in decai_check or "RCmd.Use()" in decai_check:
            print(f"[!] The decai plugin is not available.")
            # Try with a traditional decompiler (r2ghidra) as an alternative
            print(f"[+] Trying with r2ghidra decompiler as an alternative.")
            r2.cmd(f"s {function_offset}")
            return r2.cmd("pdg")
        
        # Go to the function address
        r2.cmd(f"s {function_offset}")
        
        # Verify that we are at the correct address
        current_pos = r2.cmdj("sj")
        if not current_pos or not isinstance(current_pos, dict) or 'offset' not in current_pos:
            return f"Could not position at the function address: {function_name}"
        
        # Try to decompile using decai
        print(f"[+] Decompiling {function_name} with decai...")
        
        # Configure decai to use ollama with the appropriate model
        # Get available models
        try:
            models = r2.cmd("ollama list").split("\n")
            selected_model = None
            
            # Look for a suitable model for decompilation
            preferred_models = ["qwen2:5b-coder", "codellama:7b", "llama3", "mistral", "phi"]
            for model_line in models:
                for preferred in preferred_models:
                    if preferred in model_line.lower():
                        # Extract model name (first field)
                        model_parts = model_line.split()
                        if model_parts:
                            selected_model = model_parts[0]
                            break
                if selected_model:
                    break
            
            if not selected_model and len(models) > 1:
                # If we didn't find a preferred model, use the first available one
                try:
                    model_parts = models[1].split()
                    if model_parts:
                        selected_model = model_parts[0]
                except:
                    pass
            
            # Configure the model
            if selected_model:
                print(f"[+] Using model: {selected_model}")
                r2.cmd("decai -e api=ollama")
                r2.cmd(f"decai -e model={selected_model}")
            else:
                print("[!] No available models found in Ollama.")
                print("[+] Using default decai configuration.")
        except Exception as e:
            print(f"[!] Error getting models from Ollama: {str(e)}")
            print("[+] Using default decai configuration.")
        
        # Execute commands in a more controlled sequence with error checking
        try:
            # First attempt: use direct decompilation option
            decompiled_code = r2.cmd("decai -d")
            
            # Check if the result is useful
            if decompiled_code and len(decompiled_code) > 30 and "Error" not in decompiled_code and "error" not in decompiled_code.lower():
                return decompiled_code
                
            # Second attempt: use recursive decompilation
            print("[+] First method unsuccessful, trying with recursive decompilation...")
            decompiled_code = r2.cmd("decai -dr")
            
            # Check if the result is useful
            if decompiled_code and len(decompiled_code) > 30 and "Error" not in decompiled_code and "error" not in decompiled_code.lower():
                return decompiled_code
                
            # Third attempt: query the model directly
            print("[+] Previous methods unsuccessful, trying direct query...")
            asm_code = r2.cmd("pdf")
            query = f"Decompile this assembly code to C:\n{asm_code}"
            decompiled_code = r2.cmd(f"decai -q '{query}'")
            
            # Check if the result is useful
            if decompiled_code and len(decompiled_code) > 30 and "Error" not in decompiled_code and "error" not in decompiled_code.lower():
                return decompiled_code
                
            # If no decai method works, try with r2ghidra
            print("[!] Could not decompile with decai, trying with r2ghidra...")
            return r2.cmd("pdg")
            
        except Exception as e:
            print(f"[!] Error during decompilation with decai: {str(e)}")
            # In case of error, try with r2ghidra
            try:
                return r2.cmd("pdg")
            except:
                return f"Error decompiling with decai: {str(e)}"
    except Exception as e:
        print(f"[!] General error in decompile_with_decai: {str(e)}")
        try:
            # In case of error, try with r2ghidra
            return r2.cmd("pdg")
        except:
            return f"Error decompiling with decai: {str(e)}"

def decompile_function(r2, function_name, decompiler_type=None):
    """
    Decompiles a function using the specified decompiler.
    
    Args:
        r2: r2pipe instance.
        function_name: Name of the function to decompile.
        decompiler_type: Type of decompiler to use.
        
    Returns:
        str: Decompiled code or error message.
    """
    try:
        # Get decompiler type from configuration if not specified
        if decompiler_type is None:
            decompiler_type = CONFIG["decompiler"]["type"]
        
        # Get decompiler options
        decompiler_options = CONFIG["decompiler"].get("options", {})
        max_retries = decompiler_options.get("max_retries", 3)
        ignore_unknown_branches = decompiler_options.get("ignore_unknown_branches", True)
        fallback_to_asm = decompiler_options.get("fallback_to_asm", True)
        clean_error_messages = decompiler_options.get("clean_error_messages", True)
        use_alternative_decompiler = decompiler_options.get("use_alternative_decompiler", True)
        
        # If r2ai is requested, change to default since r2ai is not a decompiler
        if decompiler_type == "r2ai":
            print("[!] r2ai is not a decompiler. Changing to default decompiler.")
            decompiler_type = "default"
        
        def clean_decompiled_output(decompiled_text):
            """Clean decompiled output by removing error messages and warnings."""
            if not decompiled_text:
                return decompiled_text
                
            lines = decompiled_text.split("\n")
            cleaned_lines = []
            
            for line in lines:
                # Skip error messages and warnings
                if any(x in line.lower() for x in ["error:", "warn:", "warning:", "unknown branch"]):
                    continue
                # Skip empty lines after cleaning
                if line.strip():
                    cleaned_lines.append(line)
            
            return "\n".join(cleaned_lines)
        
        def try_decompile_with_command(r2, command, function_name):
            """Try to decompile with a specific command and handle errors."""
            try:
                r2.cmd(f"s {function_name}")
                decompiled = r2.cmd(command)
                
                if clean_error_messages:
                    decompiled = clean_decompiled_output(decompiled)
                
                if decompiled and len(decompiled.strip()) > 10:
                    return decompiled
                return None
            except Exception:
                return None
        
        # Decompile according to the selected decompiler type
        if decompiler_type == "r2ghidra":
            # Try to decompile with r2ghidra (pdg)
            decompiled = try_decompile_with_command(r2, "pdg", function_name)
            
            if decompiled:
                return decompiled
            elif use_alternative_decompiler:
                # Try with pdd as an alternative
                return try_decompile_with_command(r2, "pdd", function_name)
                
        elif decompiler_type == "r2dec":
            # Try to decompile with r2dec (pdd)
            decompiled = try_decompile_with_command(r2, "pdd", function_name)
            
            if decompiled:
                return decompiled
            elif use_alternative_decompiler:
                # Try with pdg as an alternative
                return try_decompile_with_command(r2, "pdg", function_name)
                
        elif decompiler_type == "decai":
            return decompile_with_decai(r2, function_name)
                
        elif decompiler_type == "default":
            # Try decompilers in order of preference
            decompilers_to_try = [
                ("r2ghidra", "pdg"),
                ("r2dec", "pdd"),
                ("default", "pdc")
            ]
            
            for decomp_name, command in decompilers_to_try:
                if decomp_name == "default" or check_decompiler_available(decomp_name, print_message=False):
                    decompiled = try_decompile_with_command(r2, command, function_name)
                    if decompiled:
                        return decompiled
            
            # If all else fails and fallback_to_asm is enabled, return disassembly
            if fallback_to_asm:
                return r2.cmd("pdf")
            return "Error: Could not decompile function"
        else:
            # Unknown decompiler, use default decompiler
            print(f"[!] Unknown decompiler: {decompiler_type}. Using default decompiler.")
            return decompile_function(r2, function_name, "default")
            
    except Exception as e:
        # In case of error, return an error message
        return f"Error decompiling {function_name}: {str(e)}"

def decompile_with_selected_decompiler(r2, functions, banned_functions=None, verbose=True, decompiler_type=None):
    """
    Uses the selected decompiler to decompile the binary and look for banned functions.
    
    Args:
        r2: r2pipe instance.
        functions: List of functions to decompile.
        banned_functions: List of banned functions already detected.
        verbose: If True, shows detailed information.
        decompiler_type: Type of decompiler to use. If None, uses the one from CONFIG.
        
    Returns:
        list: List of detected banned functions.
    """
    if banned_functions is None:
        banned_functions = []
    
    detected_functions = []
    
    # Get decompiler type from configuration if not specified
    if decompiler_type is None:
        decompiler_type = CONFIG["decompiler"]["type"]
    
    if verbose:
        print(f"[+] Attempting to decompile with {decompiler_type}...")
    
    # Check if the decompiler is available (with an initial message)
    is_decompiler_available = check_decompiler_available(decompiler_type, print_message=True)
    if not is_decompiler_available:
        if verbose:
            if decompiler_type in ["decai"]:
                print(f"[!] The AI assistant plugin {decompiler_type} is not available.")
            else:
                print(f"[!] The decompiler {decompiler_type} is not available.")
            print("[*] Checking available alternatives...")
        
        # Try to automatically find an alternative decompiler
        alternatives = ["r2ghidra", "r2dec"]  # Only traditional decompilers
        selected_alternative = None
        
        for alt in alternatives:
            if alt != decompiler_type and check_decompiler_available(alt, print_message=False):
                selected_alternative = alt
                if verbose:
                    print(f"[+] The decompiler '{alt}' is available as an alternative.")
                    print(f"[+] Using '{alt}' automatically.")
                break
        
        if selected_alternative:
            decompiler_type = selected_alternative
        else:
            # If no alternative, use the default
            decompiler_type = "default"
            if verbose:
                print("[!] No available alternatives found.")
                print("[+] Using the default decompiler.")
    
    # Verify that a valid function list was passed
    if not functions:
        if verbose:
            print("[!] No functions found to decompile")
        return detected_functions
    
    if verbose:
        print(f"[+] Decompiling {len(functions)} functions with {decompiler_type}...")
    
    # Threshold for small functions
    small_function_threshold = CONFIG.get("small_function_threshold", 20)
    skip_small_functions = CONFIG.get("skip_small_functions", True)
    
    # Set counter for periodic logging
    total_functions = len(functions)
    log_interval = max(1, total_functions // 10)  # Divide into approximately 10 updates
    success_count = 0
    error_count = 0
    
    # For each function, decompile and look for unsafe functions
    for i, func in enumerate(functions):
        func_addr = func.get("offset")
        func_name = func.get("name")
        
        # Skip very small functions or symbols if configured that way
        if skip_small_functions and func.get("size", 0) < small_function_threshold:
            continue
        
        # Show progress periodically
        if verbose and (i % log_interval == 0 or i == total_functions - 1):
            percent = (i+1) / total_functions * 100
            print(f"[+] Progress: {i+1}/{total_functions} functions ({percent:.1f}%) - Successes: {success_count}, Errors: {error_count}")
        
        # Detailed logging for specific functions (if verbose)
        if verbose and (i % 50 == 0):
            print(f"[+] Decompiling {func_name} with {decompiler_type}...")
        
        # Decompile the function with the selected decompiler
        try:
            decompiled = decompile_function(r2, func_name, decompiler_type)
            
            # Verify that the decompilation is a valid text string
            if not isinstance(decompiled, str):
                if verbose and i % log_interval == 0:
                    print(f"[!] Error: The decompilation of {func_name} is not a valid text string")
                error_count += 1
                continue
                
            # If the decompilation is empty or has common errors, count as error but continue
            if not decompiled or "error" in decompiled.lower() or "invalid" in decompiled.lower():
                error_count += 1
                continue
                
            success_count += 1
                
            # Look for unsafe functions in the decompiled code
            for insecure_func in INSECURE_FUNCTIONS:
                try:
                    pattern = r'\b' + re.escape(insecure_func) + r'\s*\('
                    if re.search(pattern, decompiled, re.IGNORECASE):
                        # Create a dictionary with the function information
                        detected_info = {
                            "name": func_name,
                            "address": func_addr,
                            "banned_functions": [insecure_func],
                            "match_type": "decompilation"
                        }
                        
                        # Add to the list of banned functions
                        detected_functions.append(detected_info)
                        
                        if verbose:
                            print(f"[!] Unsafe function detected in {func_name}: {insecure_func}")
                        
                        # Exit the inner loop, we've found an unsafe function
                        break
                except Exception as e:
                    if verbose and i % log_interval == 0:
                        print(f"[!] Error searching for patterns in {func_name}: {str(e)}")
                    continue
        except Exception as e:
            error_count += 1
            if verbose and i % log_interval == 0:
                print(f"[!] Error decompiling {func_name}: {str(e)}")
            continue
    
    # Final summary
    if verbose:
        print(f"[+] Decompilation analysis completed:")
        print(f"   - Total functions analyzed: {total_functions}")
        print(f"   - Successful decompilations: {success_count}")
        print(f"   - Errors: {error_count}")
        print(f"   - Unsafe functions detected: {len(detected_functions)}")
    
    return detected_functions

def get_function_info(r2, function_name):
    """
    Gets function information from radare2.
    
    Args:
        r2: r2pipe instance.
        function_name: Name of the function to look for.
        
    Returns:
        dict: Function information or None if not found.
    """
    try:
        # Try to get function information with cmdj
        function_info = r2.cmdj(f"afij @ {function_name}")
        
        # Check if information was found
        if not function_info:
            return None
            
        # If it's a list, take the first element
        if isinstance(function_info, list):
            if len(function_info) == 0:
                return None
            return function_info[0]  # Return the first element
            
        # If it's already a dictionary, return it directly
        if isinstance(function_info, dict):
            return function_info
            
        # If it's neither a list nor a dictionary, return None
        return None
    except Exception as e:
        print(f"[!] Error getting function information {function_name}: {str(e)}")
        return None 