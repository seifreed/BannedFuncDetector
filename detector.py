#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Banned functions detection module
Author: Marc Rivero | @seifreed
"""

import os
import re
import json

# List of known insecure functions, categorized by type
INSECURE_FUNCTIONS = {
    # Insecure string handling functions
    "string": [
        "strcpy", "strcat", "sprintf", "vsprintf", "gets", "strlen",
        "scanf", "fscanf", "sscanf", "vscanf", "vfscanf", "vsscanf",
        "strtok", "strncpy", "strncat", "strchr", "strrchr", "strspn",
        "strcspn", "strpbrk", "strstr", "stricmp", "strcasecmp"
    ],
    # Insecure memory management functions
    "memory": [
        "memcpy", "memmove", "memset", "memcmp", "malloc", "calloc",
        "realloc", "free", "alloca", "CopyMemory", "WriteProcessMemory"
    ],
    # Insecure file handling functions
    "file": [
        "fopen", "fclose", "fread", "fwrite", "fprintf", "fgets",
        "fflush", "ferror", "feof", "fseek", "ftell", "rewind", 
        "open", "close", "read", "write", "lseek", "unlink", "remove"
    ],
    # Potentially insecure network functions
    "network": [
        "socket", "connect", "accept", "bind", "listen", "send", 
        "recv", "sendto", "recvfrom", "gethostbyname", "gethostbyaddr",
        "inet_addr", "inet_ntoa", "inet_pton", "inet_ntop", "setsockopt",
        "getsockname", "getpeername"
    ],
    # Potentially insecure process and signal functions
    "process": [
        "system", "popen", "pclose", "exec", "execl", "execle", "execlp",
        "execv", "execve", "execvp", "fork", "waitpid", "signal", "kill",
        "sigaction", "sigismember", "sigemptyset", "sigfillset"
    ],
    # Standard I/O functions
    "stdio": [
        "printf", "putchar", "puts", "getc", "getchar", "vprintf", 
        "vfprintf", "vsprintf"
    ],
    # Environment and user functions
    "environment": [
        "getenv", "setenv", "putenv", "getlogin", "getpwuid", "getpwnam",
        "getpwent", "endpwent"
    ],
    # Directory functions
    "directory": [
        "opendir", "readdir", "closedir", "scandir", "mkdir", "rmdir"
    ],
    # Time and wait functions
    "time": [
        "time", "ctime", "asctime", "localtime", "gmtime", "strftime",
        "mktime", "gettimeofday", "nanosleep", "usleep", "sleep", "poll"
    ]
}

def get_banned_functions_by_name(r2, functions):
    """
    Searches for banned functions by name in the function list.
    
    Args:
        r2: r2pipe instance.
        functions: List of functions to analyze.
        
    Returns:
        list: List of banned functions found.
    """
    banned_functions = []
    
    # Create a flat list of all insecure functions
    flat_insecure_functions = []
    for category, funcs in INSECURE_FUNCTIONS.items():
        flat_insecure_functions.extend(funcs)
    
    # Search for banned functions by name
    for func in functions:
        # Get the full function name
        func_name = func.get('name', '')
        
        # Look for matches with banned functions
        for banned in flat_insecure_functions:
            # For each banned function, look for exact matches or as a subfunction
            if (func_name.endswith('.' + banned) or 
                func_name == banned or 
                func_name.endswith('_' + banned) or 
                func_name.endswith('.' + banned.lower()) or 
                func_name == banned.lower()):
                
                # If a match is found, verify that it's not a false positive
                # For example, memcpy could be part of other names like __memcpy_sse2_unaligned
                if func_name.replace('sym.', '') == banned or \
                   func_name.endswith('.' + banned) or \
                   func_name.endswith('_' + banned) or \
                   ('sym.' + banned) in func_name:
                    
                    # Find which category the banned function belongs to
                    function_category = None
                    for category, funcs in INSECURE_FUNCTIONS.items():
                        if banned in funcs:
                            function_category = category
                            break
                    
                    # Add to the list of banned functions with additional information
                    print(f"[+] Insecure function detected by name: {func_name}")
                    banned_func = {
                        'name': func_name,
                        'address': func.get('offset', 0),
                        'size': func.get('size', 0),
                        'type': function_category if function_category else 'unknown',
                        'banned_functions': [banned],
                        'detection_method': 'name_match'
                    }
                    
                    print(f"[+] Insecure function found: {func_name} at {hex(banned_func['address'])}")
                    banned_functions.append(banned_func)
                    break
    
    return banned_functions

def get_banned_functions_in_imports(r2):
    """
    Searches for banned functions in the binary's imports.
    
    Args:
        r2: r2pipe instance.
        
    Returns:
        list: List of banned functions found in imports.
    """
    banned_functions = []
    
    # Get imports
    imports = r2.cmdj("iij")
    if not imports:
        return banned_functions
    
    for imp in imports:
        imp_name = imp.get("name", "")
        imp_addr = imp.get("plt", 0) or imp.get("offset", 0)
        
        # Check if the import name matches any banned function
        for banned_func in INSECURE_FUNCTIONS:
            pattern = r'\b' + re.escape(banned_func) + r'\b'
            if re.search(pattern, imp_name, re.IGNORECASE):
                # Create a dictionary with the function information
                banned_info = {
                    "name": imp_name,
                    "address": imp_addr,
                    "banned_functions": [banned_func],
                    "match_type": "import"
                }
                
                # Add to the list of banned functions
                banned_functions.append(banned_info)
                
                # Only add once if it matches
                break
    
    return banned_functions

def get_banned_functions_by_strings(r2):
    """
    Searches for banned functions in text strings of the binary.
    
    Args:
        r2: r2pipe instance.
        
    Returns:
        list: List of banned functions found in strings.
    """
    banned_functions = []
    
    # Get strings from the binary
    strings = r2.cmdj("izzj")
    if not strings:
        return banned_functions
    
    # Process each string
    for s in strings.get("strings", []):
        string_value = s.get("string", "")
        string_addr = s.get("paddr", 0)
        
        # Check if the string contains any banned function
        for banned_func in INSECURE_FUNCTIONS:
            pattern = r'\b' + re.escape(banned_func) + r'\b'
            if re.search(pattern, string_value, re.IGNORECASE):
                # Find references to the string
                refs = r2.cmdj(f"axtj @ {string_addr}")
                
                if refs:
                    for ref in refs:
                        ref_addr = ref.get("from", 0)
                        ref_func = r2.cmdj(f"afij @ {ref_addr}")
                        
                        if ref_func and len(ref_func) > 0:
                            func_name = ref_func[0].get("name", "unknown")
                            func_addr = ref_func[0].get("offset", 0)
                            
                            # Create a dictionary with the function information
                            banned_info = {
                                "name": func_name,
                                "address": func_addr,
                                "banned_functions": [banned_func],
                                "match_type": "string_reference",
                                "string": string_value
                            }
                            
                            # Add to the list of banned functions
                            banned_functions.append(banned_info)
                
                # Only add once if it matches
                break
    
    return banned_functions

def analyze_with_decai(r2, function_name):
    """
    Analyzes a function using the decai decompiler to look for banned functions.
    
    Args:
        r2: r2pipe instance.
        function_name: Name of the function to analyze.
        
    Returns:
        list: List of banned functions found.
    """
    banned_functions = []
    
    # Configure decai to use ollama
    r2.cmd("decai -e api=ollama")
    r2.cmd("decai -e model=qwen2:5b-coder")
    
    # Decompile the function
    decompiled = r2.cmd(f"decai -d {function_name}")
    
    # Look for banned functions in the decompiled code
    for banned_func in INSECURE_FUNCTIONS:
        pattern = r'\b' + re.escape(banned_func) + r'\s*\('
        if re.search(pattern, decompiled, re.IGNORECASE):
            # Get function information
            func_info = r2.cmdj(f"afij @ {function_name}")
            if func_info and len(func_info) > 0:
                func_addr = func_info[0].get("offset", 0)
                
                # Create a dictionary with the function information
                banned_info = {
                    "name": function_name,
                    "address": func_addr,
                    "banned_functions": [banned_func],
                    "match_type": "decai_decompilation"
                }
                
                # Add to the list of banned functions
                banned_functions.append(banned_info)
                
                # Print information
                print(f"[+] Insecure function detected in decompiled code: {function_name}")
                print(f"[+] Insecure function found: {function_name} at {hex(func_addr)}")
    
    return banned_functions

def analyze_binary(r2, options=None):
    """
    Analyzes a complete binary looking for banned functions.
    
    Args:
        r2: r2pipe instance.
        options: Additional options for analysis.
        
    Returns:
        dict: Analysis results.
    """
    # Perform basic analysis
    r2.cmd("aaa")
    
    # Get all functions
    functions = r2.cmdj("aflj")
    if not functions:
        return {"error": "No functions found"}
    
    # Search for banned functions by name
    banned_by_name = get_banned_functions_by_name(r2, functions)
    
    # Search for banned functions in imports
    banned_in_imports = get_banned_functions_in_imports(r2)
    
    # Combine results
    all_banned = banned_by_name + banned_in_imports
    
    # Remove duplicates
    unique_banned = []
    addresses = set()
    
    for func in all_banned:
        addr = func["address"]
        if addr not in addresses:
            unique_banned.append(func)
            addresses.add(addr)
    
    # Generate report
    report = {
        "total_functions": len(functions),
        "unsafe_functions": len(unique_banned),
        "results": unique_banned
    }
    
    return report 