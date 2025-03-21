#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Utilities module
Author: Marc Rivero | @seifreed
"""

import os
import re
import magic
import subprocess
import requests
import time
from config import CONFIG

# Complete list of functions banned by Microsoft
BANNED_FUNCTIONS = {
    # Banned string copy functions
    "strcpy", "strcpyA", "strcpyW", "wcscpy", "_tcscpy", "_mbscpy", "StrCpy", "StrCpyA", "StrCpyW",
    "lstrcpy", "lstrcpyA", "lstrcpyW", "_tccpy", "_mbccpy", "_ftcscpy", "strncpy", "wcsncpy",
    "_tcsncpy", "_mbsncpy", "_mbsnbcpy", "StrCpyN", "StrCpyNA", "StrCpyNW", "StrNCpy",
    "strcpynA", "StrNCpyA", "StrNCpyW", "lstrcpyn", "lstrcpynA", "lstrcpynW",

    # Banned string concatenation functions
    "strcat", "strcatA", "strcatW", "wcscat", "_tcscat", "_mbscat", "StrCat", "StrCatA", "StrCatW",
    "lstrcat", "lstrcatA", "lstrcatW", "StrCatBuff", "StrCatBuffA", "StrCatBuffW", "StrCatChainW",
    "_tccat", "_mbccat", "_ftcscat", "strncat", "wcsncat", "_tcsncat", "_mbsncat", "_mbsnbcat",
    "StrCatN", "StrCatNA", "StrCatNW", "StrNCat", "StrNCatA", "StrNCatW", "lstrncat",
    "lstrcatnA", "lstrcatnW", "lstrcatn",

    # Banned string format functions (sprintf)
    "sprintfW", "sprintfA", "wsprintf", "wsprintfW", "wsprintfA", "sprintf", "swprintf",
    "_stprintf", "wvsprintf", "wvsprintfA", "wvsprintfW", "vsprintf", "_vstprintf", "vswprintf",

    # Banned string format functions with limits ("n" sprintf)
    "_snwprintf", "_snprintf", "_sntprintf", "nsprintf",

    # Banned string format functions with variable arguments
    "wvsprintf", "wvsprintfA", "wvsprintfW", "vsprintf", "_vstprintf", "vswprintf",

    # Banned string input functions
    "gets", "_getts", "_gettws",

    # Banned string token functions
    "strtok", "_tcstok", "wcstok", "_mbstok",

    # Banned maketoken functions
    "makepath", "_tmakepath", "_makepath", "_wmakepath",

    # Banned splitpath functions
    "splitpath", "_tsplitpath", "_splitpath", "_wsplitpath",

    # Banned scanf functions
    "scanf", "wscanf", "_tscanf", "sscanf", "swscanf", "_stscanf",

    # Banned itoa functions
    "itoa", "_itoa", "_itow", "_i64toa", "_i64tow", "_ui64toa", "_ui64tot", "_ui64tow", "_ultoa",
    "_ultot", "_ultow",

    # Banned memory manipulation functions
    "memcpy", "RtlCopyMemory", "CopyMemory", "wmemcpy",

    # Banned memory manipulation functions with limits
    "memccpy",

    # Banned memory manipulation functions with overlap
    "memmove", "RtlMoveMemory", "MoveMemory", "wmemmove",

    # Banned memory manipulation functions with filling
    "memset", "RtlFillMemory", "FillMemory", "wmemset",

    # Banned memory manipulation functions with comparison
    "memcmp", "RtlCompareMemory", "CompareMemory", "wmemcmp",

    # Banned memory manipulation functions with searching
    "memchr", "wmemchr",

    # Banned file manipulation functions
    "fopen", "_wfopen", "fclose", "fread", "fwrite", "fprintf", "fscanf", "fgets", "fputs",
    "fseek", "ftell", "rewind", "fflush", "ferror", "feof", "clearerr", "tmpfile", "tmpnam",
    "freopen", "_wfreopen", "fgetpos", "fsetpos", "ungetc", "setvbuf", "setbuf", "perror",
    "remove", "rename", "_wrename", "fputc", "fgetc", "putc", "getc", "putchar", "getchar",

    # Banned directory manipulation functions
    "opendir", "readdir", "closedir", "rewinddir", "scandir", "seekdir", "telldir",

    # Banned process manipulation functions
    "system", "popen", "pclose", "execl", "execle", "execlp", "execv", "execve", "execvp",
    "execvpe", "_execl", "_execle", "_execlp", "_execlpe", "_execv", "_execve", "_execvp",
    "_execvpe", "spawn", "_spawn", "_spawnl", "_spawnle", "_spawnlp", "_spawnlpe", "_spawnv",
    "_spawnve", "_spawnvp", "_spawnvpe", "fork", "vfork", "wait", "waitpid",

    # Banned signal manipulation functions
    "signal", "raise", "kill", "sigaction", "sigemptyset", "sigfillset", "sigaddset",
    "sigdelset", "sigismember", "sigpending", "sigprocmask", "sigsuspend", "sigwait",

    # Banned time manipulation functions
    "time", "ctime", "asctime", "gmtime", "localtime", "mktime", "strftime", "strptime",
    "clock", "difftime", "sleep", "usleep", "nanosleep",

    # Banned environment manipulation functions
    "getenv", "setenv", "putenv", "unsetenv", "clearenv", "_wgetenv", "_wputenv", "_wsetenv",

    # Banned user manipulation functions
    "getlogin", "getpwnam", "getpwuid", "getgrnam", "getgrgid", "getspnam", "getspent",
    "setpwent", "endpwent", "setgrent", "endgrent", "setspent", "endspent",

    # Banned network manipulation functions
    "socket", "connect", "bind", "listen", "accept", "send", "recv", "sendto", "recvfrom",
    "gethostbyname", "gethostbyaddr", "getservbyname", "getservbyport", "getaddrinfo",
    "freeaddrinfo", "getnameinfo", "inet_ntoa", "inet_addr", "inet_aton", "inet_ntop", "inet_pton",

    # Banned thread manipulation functions
    "pthread_create", "pthread_join", "pthread_detach", "pthread_cancel", "pthread_exit",
    "pthread_attr_init", "pthread_attr_destroy", "pthread_attr_setdetachstate",
    "pthread_attr_getdetachstate", "pthread_attr_setschedpolicy", "pthread_attr_getschedpolicy",
    "pthread_attr_setschedparam", "pthread_attr_getschedparam", "pthread_attr_setstacksize",
    "pthread_attr_getstacksize", "pthread_attr_setstackaddr", "pthread_attr_getstackaddr",
    "pthread_attr_setstack", "pthread_attr_getstack", "pthread_attr_setguardsize",
    "pthread_attr_getguardsize", "pthread_attr_setscope", "pthread_attr_getscope",
    "pthread_mutex_init", "pthread_mutex_destroy", "pthread_mutex_lock", "pthread_mutex_trylock",
    "pthread_mutex_unlock", "pthread_mutex_timedlock", "pthread_mutexattr_init",
    "pthread_mutexattr_destroy", "pthread_mutexattr_setpshared", "pthread_mutexattr_getpshared",
    "pthread_mutexattr_settype", "pthread_mutexattr_gettype", "pthread_mutexattr_setprotocol",
    "pthread_mutexattr_getprotocol", "pthread_mutexattr_setprioceiling",
    "pthread_mutexattr_getprioceiling", "pthread_cond_init", "pthread_cond_destroy",
    "pthread_cond_wait", "pthread_cond_timedwait", "pthread_cond_signal", "pthread_cond_broadcast",
    "pthread_condattr_init", "pthread_condattr_destroy", "pthread_condattr_setpshared",
    "pthread_condattr_getpshared", "pthread_condattr_setclock", "pthread_condattr_getclock",
    "pthread_rwlock_init", "pthread_rwlock_destroy", "pthread_rwlock_rdlock",
    "pthread_rwlock_tryrdlock", "pthread_rwlock_timedrdlock", "pthread_rwlock_wrlock",
    "pthread_rwlock_trywrlock", "pthread_rwlock_timedwrlock", "pthread_rwlock_unlock",
    "pthread_rwlockattr_init", "pthread_rwlockattr_destroy", "pthread_rwlockattr_setpshared",
    "pthread_rwlockattr_getpshared", "pthread_spin_init", "pthread_spin_destroy",
    "pthread_spin_lock", "pthread_spin_trylock", "pthread_spin_unlock", "pthread_barrier_init",
    "pthread_barrier_destroy", "pthread_barrier_wait", "pthread_barrierattr_init",
    "pthread_barrierattr_destroy", "pthread_barrierattr_setpshared",
    "pthread_barrierattr_getpshared", "pthread_key_create", "pthread_key_delete",
    "pthread_setspecific", "pthread_getspecific", "pthread_once"
}

def is_pe_file(file_path):
    """Checks if a file is a PE executable."""
    try:
        file_type = magic.from_file(file_path)
        return "PE32" in file_type or "PE32+" in file_type
    except Exception:
        return False

def find_pe_files(directory):
    """Finds all PE files in a directory."""
    pe_files = []
    
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            
            # Check if it's a PE file
            if is_pe_file(file_path):
                pe_files.append(file_path)
    
    return pe_files

def check_r2ai_server_available(server_url="http://localhost:8080"):
    """Checks if r2ai-server is available at the specified URL."""
    try:
        response = requests.get(f"{server_url}/ping", timeout=2)
        if response.status_code == 200:
            print(f"[+] r2ai-server detected at {server_url}")
            
            # Try to get the list of available models
            try:
                models_response = requests.get(f"{server_url}/models", timeout=2)
                if models_response.status_code == 200:
                    models_data = models_response.json()
                    if "models" in models_data and models_data["models"]:
                        print("[+] Models available in r2ai-server:")
                        for model in models_data["models"][:5]:
                            print(f"    - {model}")
                        if len(models_data["models"]) > 5:
                            print(f"    ... and {len(models_data['models']) - 5} more")
                    else:
                        print("[!] No available models found in r2ai-server")
            except Exception as e:
                print(f"[!] Error getting the list of models: {str(e)}")
            
            return True
        else:
            print(f"[!] r2ai-server is not responding correctly at {server_url}")
            return False
    except Exception as e:
        print(f"[!] Error connecting to r2ai-server: {str(e)}")
        
        # Check if r2ai-server is installed
        try:
            result = subprocess.run(['r2ai-server', '-h'], capture_output=True, text=True)
            if result.returncode == 0:
                print("[+] r2ai-server is installed but not running")
                
                # Ask if you want to start r2ai-server
                start_server = input("Do you want to start r2ai-server? (y/n): ").lower()
                if start_server in ['s', 'si', 'sí', 'y', 'yes']:
                    print("[+] Starting r2ai-server...")
                    
                    # Get the list of available models
                    models_result = subprocess.run(['r2ai-server', '-m'], capture_output=True, text=True)
                    if models_result.returncode == 0 and models_result.stdout.strip():
                        print("[+] Models available for r2ai-server:")
                        models_lines = models_result.stdout.strip().split('\n')
                        for line in models_lines[:5]:
                            print(f"    {line}")
                        if len(models_lines) > 5:
                            print(f"    ... and {len(models_lines) - 5} more")
                        
                        # Ask which model to use
                        model = input("Which model do you want to use? (leave blank to use the default): ").strip()
                        
                        # Start r2ai-server with the selected model
                        try:
                            if model:
                                server_process = subprocess.Popen(['r2ai-server', '-l', 'r2ai', '-m', model], 
                                                               stdout=subprocess.PIPE, 
                                                               stderr=subprocess.PIPE)
                            else:
                                server_process = subprocess.Popen(['r2ai-server', '-l', 'r2ai'], 
                                                               stdout=subprocess.PIPE, 
                                                               stderr=subprocess.PIPE)
                            
                            print("[+] r2ai-server started in the background")
                            print("[+] Waiting for the server to be available...")
                            
                            # Wait for the server to be available
                            for _ in range(10):
                                try:
                                    response = requests.get(f"{server_url}/ping", timeout=1)
                                    if response.status_code == 200:
                                        print("[+] r2ai-server is available")
                                        return True
                                except Exception:
                                    time.sleep(1)
                            
                            print("[!] Timeout. r2ai-server is not responding")
                            return False
                        except Exception as e:
                            print(f"[!] Error starting r2ai-server: {str(e)}")
                            return False
                    else:
                        print("[!] Could not get available models")
                        return False
                else:
                    print("[!] r2ai-server startup canceled")
                    return False
            else:
                print("[!] r2ai-server is not installed")
                
                # Ask if you want to install r2ai-server
                install_server = input("Do you want to install r2ai-server? (y/n): ").lower()
                if install_server in ['s', 'si', 'sí', 'y', 'yes']:
                    print("[+] Installing r2ai-server...")
                    try:
                        subprocess.run(['r2pm', 'install', 'r2ai-server'], check=True)
                        print("[+] r2ai-server installed successfully")
                        
                        # Try to start r2ai-server
                        return check_r2ai_server_available(server_url)
                    except Exception as e:
                        print(f"[!] Error installing r2ai-server: {str(e)}")
                        return False
                else:
                    print("[!] r2ai-server installation canceled")
                    return False
        except Exception as e:
            print(f"[!] Error verifying r2ai-server installation: {str(e)}")
            return False
        
        return False 