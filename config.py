#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Configuration module
Author: Marc Rivero | @seifreed
"""
import json
import os

# Default configuration
DEFAULT_CONFIG = {
    "decompiler": {
        "type": "default",
        "options": {
            "default": {
                "enabled": True,
                "command": "pdc",
                "description": "Default radare2 decompiler"
            },
            "r2ghidra": {
                "enabled": True,
                "command": "pdg",
                "description": "r2ghidra decompiler",
                "error_handling": {
                    "ignore_unknown_branches": True,
                    "clean_error_messages": True,
                    "fallback_to_asm": True
                }
            },
            "r2dec": {
                "enabled": True,
                "command": "pdd",
                "description": "r2dec decompiler",
                "error_handling": {
                    "ignore_unknown_branches": True,
                    "clean_error_messages": True,
                    "fallback_to_asm": True
                }
            },
            "r2ai": {
                "enabled": True,
                "command": "pdai",
                "model": "hhao/qwen2.5-coder-tools:32b",
                "description": "AI-based decompiler (r2ai)",
                "advanced_options": {
                    "temperature": 0.7,
                    "context": 8192,
                    "max_tokens": 4096,
                    "system_prompt": "You are a reverse engineering assistant focused on decompiling assembly code into clean, human-readable C code."
                }
            },
            "decai": {
                "enabled": True,
                "command": "decai -d",
                "description": "AI-based decompiler (decai)",
                "api": "ollama",
                "model": "qwen2:5b-coder",
                "prompt": "Rewrite this function and respond ONLY with code, NO explanations, NO markdown, Change 'goto' into if/else/for/while, Simplify as much as possible, use better variable names, take function arguments and strings from comments like 'string:'",
                "host": "http://localhost",
                "port": 11434
            },
            "r2ai-server": {
                "enabled": True,
                "command": "pdai",
                "server_url": "http://localhost:8080",
                "model": "mistral-7b-instruct-v0.2.Q2_K",
                "description": "AI-based decompiler (r2ai-server)",
                "advanced_options": {
                    "temperature": 0.7,
                    "max_tokens": 4096,
                    "system_prompt": "You are a reverse engineering assistant focused on decompiling assembly code into clean, human-readable C code."
                }
            },
            "ignore_unknown_branches": True,
            "max_retries": 3,
            "fallback_to_asm": True,
            "error_threshold": 0.1,  # Maximum allowed error rate before falling back to simpler analysis
            "clean_error_messages": True,  # Remove error messages from output
            "use_alternative_decompiler": True  # Try alternative decompiler on error
        }
    },
    "output": {
        "directory": "output",
        "format": "json",
        "open_results": False,
        "verbose": False
    },
    "analysis": {
        "parallel": True,
        "max_workers": 4,
        "timeout": 600,
        "worker_limit": None
    },
    "max_workers": 10,
    "skip_small_functions": True,
    "small_function_threshold": 10,
    "r2pipe_threads": 10
}

# Global variable for configuration
CONFIG = DEFAULT_CONFIG.copy()

def load_config(config_file="config.json"):
    """Loads configuration from a JSON file."""
    global CONFIG
    try:
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                user_config = json.load(f)
            
            # Update configuration with user values
            for key, value in user_config.items():
                if key in CONFIG:
                    if isinstance(CONFIG[key], dict) and isinstance(value, dict):
                        # For nested sections like 'decompiler'
                        for subkey, subvalue in value.items():
                            if subkey in CONFIG[key]:
                                if isinstance(CONFIG[key][subkey], dict) and isinstance(subvalue, dict):
                                    # For doubly nested sections like 'options'
                                    for subsubkey, subsubvalue in subvalue.items():
                                        if subsubkey in CONFIG[key][subkey]:
                                            CONFIG[key][subkey][subsubkey] = subsubvalue
                                        else:
                                            CONFIG[key][subkey][subsubkey] = subsubvalue
                                else:
                                    CONFIG[key][subkey] = subvalue
                            else:
                                CONFIG[key][subkey] = subvalue
                    else:
                        CONFIG[key] = value
                else:
                    CONFIG[key] = value
            
            print(f"[+] Configuration loaded from {config_file}")
            return True
        else:
            print(f"[!] Configuration file {config_file} not found. Default configuration will be used.")
            return False
    except Exception as e:
        print(f"[!] Error loading configuration: {str(e)}")
        print("[!] Default configuration will be used.")
        return False

def save_config(config_file="config.json"):
    """Saves current configuration to a JSON file."""
    try:
        with open(config_file, 'w') as f:
            json.dump(CONFIG, f, indent=4)
        print(f"[+] Configuration saved to {config_file}")
        return True
    except Exception as e:
        print(f"[!] Error saving configuration: {str(e)}")
        return False

def ensure_output_dir_exists(output_dir=None):
    """Ensures that the output directory exists.
    
    Args:
        output_dir: The output directory to create. If None, CONFIG["output_dir"] is used
        
    Returns:
        str: The path to the output directory
    """
    if output_dir is None:
        output_dir = CONFIG["output_dir"]
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"[+] Output directory created: {output_dir}")
    return output_dir

def get_output_path(binary_path):
    """Gets the output path for a specific binary."""
    output_dir = CONFIG["output_dir"]
    
    # Create a subdirectory based on the binary name
    binary_name = os.path.basename(binary_path)
    binary_output_dir = os.path.join(output_dir, binary_name)
    
    # Ensure that the directory exists
    if not os.path.exists(binary_output_dir):
        os.makedirs(binary_output_dir)
    
    return binary_output_dir

def get_result_filename(binary_path):
    """Gets the results filename for a specific binary."""
    output_path = get_output_path(binary_path)
    return os.path.join(output_path, "results.json")

def is_already_analyzed(binary_path):
    """Checks if a binary has already been analyzed."""
    result_file = get_result_filename(binary_path)
    if os.path.exists(result_file):
        try:
            with open(result_file, 'r') as f:
                data = json.load(f)
            
            # Check if the data is valid
            if "total_functions" in data and "unsafe_functions" in data:
                return True
        except Exception:
            pass
    
    return False 