#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Banned Functions Module

This module provides the definitive catalog of banned/insecure functions
according to Microsoft and other security guidelines. Functions are organized
by category for better analysis and reporting.

The banned functions list includes dangerous string manipulation, memory operations,
file I/O, process control, and other APIs known to cause security vulnerabilities
when used improperly.

Author: Marc Rivero | @seifreed
"""

from typing import Any

# =============================================================================
# BANNED FUNCTIONS - CATEGORIZED
# =============================================================================
# Complete list of functions banned by Microsoft and other security guidelines,
# organized by category for better analysis and reporting.

BANNED_FUNCTIONS_CATEGORIZED: dict[str, list[str]] = {
    # Banned string copy functions
    "string_copy": [
        "strcpy", "strcpyA", "strcpyW", "wcscpy", "_tcscpy", "_mbscpy",
        "StrCpy", "StrCpyA", "StrCpyW", "lstrcpy", "lstrcpyA", "lstrcpyW",
        "_tccpy", "_mbccpy", "_ftcscpy", "strncpy", "wcsncpy", "_tcsncpy",
        "_mbsncpy", "_mbsnbcpy", "StrCpyN", "StrCpyNA", "StrCpyNW", "StrNCpy",
        "strcpynA", "StrNCpyA", "StrNCpyW", "lstrcpyn", "lstrcpynA", "lstrcpynW",
    ],

    # Banned string concatenation functions
    "string_concat": [
        "strcat", "strcatA", "strcatW", "wcscat", "_tcscat", "_mbscat",
        "StrCat", "StrCatA", "StrCatW", "lstrcat", "lstrcatA", "lstrcatW",
        "StrCatBuff", "StrCatBuffA", "StrCatBuffW", "StrCatChainW", "_tccat",
        "_mbccat", "_ftcscat", "strncat", "wcsncat", "_tcsncat", "_mbsncat",
        "_mbsnbcat", "StrCatN", "StrCatNA", "StrCatNW", "StrNCat", "StrNCatA",
        "StrNCatW", "lstrncat", "lstrcatnA", "lstrcatnW", "lstrcatn",
    ],

    # Banned string format functions (sprintf family)
    "string_format": [
        "sprintfW", "sprintfA", "wsprintf", "wsprintfW", "wsprintfA", "sprintf",
        "swprintf", "_stprintf", "wvsprintf", "wvsprintfA", "wvsprintfW",
        "vsprintf", "_vstprintf", "vswprintf", "_snwprintf", "_snprintf",
        "_sntprintf", "nsprintf",
    ],

    # Banned string input functions
    "string_input": [
        "gets", "_getts", "_gettws",
    ],

    # Banned string token functions
    "string_token": [
        "strtok", "_tcstok", "wcstok", "_mbstok",
    ],

    # Banned string search/comparison functions
    "string_search": [
        "strlen", "strchr", "strrchr", "strspn", "strcspn", "strpbrk",
        "strstr", "stricmp", "strcasecmp",
    ],

    # Banned makepath/splitpath functions
    "path_manipulation": [
        "makepath", "_tmakepath", "_makepath", "_wmakepath",
        "splitpath", "_tsplitpath", "_splitpath", "_wsplitpath",
    ],

    # Banned scanf functions
    "scanf": [
        "scanf", "wscanf", "_tscanf", "sscanf", "swscanf", "_stscanf",
        "fscanf", "vscanf", "vfscanf", "vsscanf",
    ],

    # Banned itoa functions
    "number_conversion": [
        "itoa", "_itoa", "_itow", "_i64toa", "_i64tow", "_ui64toa",
        "_ui64tot", "_ui64tow", "_ultoa", "_ultot", "_ultow",
    ],

    # Banned memory manipulation functions
    "memory": [
        "memcpy", "RtlCopyMemory", "CopyMemory", "wmemcpy", "memccpy",
        "memmove", "RtlMoveMemory", "MoveMemory", "wmemmove",
        "memset", "RtlFillMemory", "FillMemory", "wmemset",
        "memcmp", "RtlCompareMemory", "CompareMemory", "wmemcmp",
        "memchr", "wmemchr", "malloc", "calloc", "realloc", "free",
        "alloca", "WriteProcessMemory",
    ],

    # Banned file manipulation functions
    "file": [
        "fopen", "_wfopen", "fclose", "fread", "fwrite", "fprintf", "fscanf",
        "fgets", "fputs", "fseek", "ftell", "rewind", "fflush", "ferror",
        "feof", "clearerr", "tmpfile", "tmpnam", "freopen", "_wfreopen",
        "fgetpos", "fsetpos", "ungetc", "setvbuf", "setbuf", "perror",
        "remove", "rename", "_wrename", "fputc", "fgetc", "putc", "getc",
        "putchar", "getchar", "open", "close", "read", "write", "lseek",
        "unlink",
    ],

    # Banned directory manipulation functions
    "directory": [
        "opendir", "readdir", "closedir", "rewinddir", "scandir", "seekdir",
        "telldir", "mkdir", "rmdir",
    ],

    # Banned process manipulation functions
    "process": [
        "system", "popen", "pclose", "execl", "execle", "execlp", "execv",
        "execve", "execvp", "execvpe", "_execl", "_execle", "_execlp",
        "_execlpe", "_execv", "_execve", "_execvp", "_execvpe", "spawn",
        "_spawn", "_spawnl", "_spawnle", "_spawnlp", "_spawnlpe", "_spawnv",
        "_spawnve", "_spawnvp", "_spawnvpe", "fork", "vfork", "wait", "waitpid",
        "exec",
    ],

    # Banned signal manipulation functions
    "signal": [
        "signal", "raise", "kill", "sigaction", "sigemptyset", "sigfillset",
        "sigaddset", "sigdelset", "sigismember", "sigpending", "sigprocmask",
        "sigsuspend", "sigwait",
    ],

    # Banned time manipulation functions
    "time": [
        "time", "ctime", "asctime", "gmtime", "localtime", "mktime",
        "strftime", "strptime", "clock", "difftime", "sleep", "usleep",
        "nanosleep", "gettimeofday", "poll",
    ],

    # Banned environment manipulation functions
    "environment": [
        "getenv", "setenv", "putenv", "unsetenv", "clearenv", "_wgetenv",
        "_wputenv", "_wsetenv",
    ],

    # Banned user manipulation functions
    "user": [
        "getlogin", "getpwnam", "getpwuid", "getgrnam", "getgrgid", "getspnam",
        "getspent", "setpwent", "endpwent", "setgrent", "endgrent", "setspent",
        "endspent", "getpwent",
    ],

    # Banned network manipulation functions
    "network": [
        "socket", "connect", "bind", "listen", "accept", "send", "recv",
        "sendto", "recvfrom", "gethostbyname", "gethostbyaddr", "getservbyname",
        "getservbyport", "getaddrinfo", "freeaddrinfo", "getnameinfo",
        "inet_ntoa", "inet_addr", "inet_aton", "inet_ntop", "inet_pton",
        "setsockopt", "getsockname", "getpeername",
    ],

    # Banned thread manipulation functions
    "thread": [
        "pthread_create", "pthread_join", "pthread_detach", "pthread_cancel",
        "pthread_exit", "pthread_attr_init", "pthread_attr_destroy",
        "pthread_attr_setdetachstate", "pthread_attr_getdetachstate",
        "pthread_attr_setschedpolicy", "pthread_attr_getschedpolicy",
        "pthread_attr_setschedparam", "pthread_attr_getschedparam",
        "pthread_attr_setstacksize", "pthread_attr_getstacksize",
        "pthread_attr_setstackaddr", "pthread_attr_getstackaddr",
        "pthread_attr_setstack", "pthread_attr_getstack",
        "pthread_attr_setguardsize", "pthread_attr_getguardsize",
        "pthread_attr_setscope", "pthread_attr_getscope",
        "pthread_mutex_init", "pthread_mutex_destroy", "pthread_mutex_lock",
        "pthread_mutex_trylock", "pthread_mutex_unlock", "pthread_mutex_timedlock",
        "pthread_mutexattr_init", "pthread_mutexattr_destroy",
        "pthread_mutexattr_setpshared", "pthread_mutexattr_getpshared",
        "pthread_mutexattr_settype", "pthread_mutexattr_gettype",
        "pthread_mutexattr_setprotocol", "pthread_mutexattr_getprotocol",
        "pthread_mutexattr_setprioceiling", "pthread_mutexattr_getprioceiling",
        "pthread_cond_init", "pthread_cond_destroy", "pthread_cond_wait",
        "pthread_cond_timedwait", "pthread_cond_signal", "pthread_cond_broadcast",
        "pthread_condattr_init", "pthread_condattr_destroy",
        "pthread_condattr_setpshared", "pthread_condattr_getpshared",
        "pthread_condattr_setclock", "pthread_condattr_getclock",
        "pthread_rwlock_init", "pthread_rwlock_destroy", "pthread_rwlock_rdlock",
        "pthread_rwlock_tryrdlock", "pthread_rwlock_timedrdlock",
        "pthread_rwlock_wrlock", "pthread_rwlock_trywrlock",
        "pthread_rwlock_timedwrlock", "pthread_rwlock_unlock",
        "pthread_rwlockattr_init", "pthread_rwlockattr_destroy",
        "pthread_rwlockattr_setpshared", "pthread_rwlockattr_getpshared",
        "pthread_spin_init", "pthread_spin_destroy", "pthread_spin_lock",
        "pthread_spin_trylock", "pthread_spin_unlock", "pthread_barrier_init",
        "pthread_barrier_destroy", "pthread_barrier_wait",
        "pthread_barrierattr_init", "pthread_barrierattr_destroy",
        "pthread_barrierattr_setpshared", "pthread_barrierattr_getpshared",
        "pthread_key_create", "pthread_key_delete", "pthread_setspecific",
        "pthread_getspecific", "pthread_once",
    ],

    # Standard I/O functions
    "stdio": [
        "printf", "putchar", "puts", "vprintf", "vfprintf",
    ],
}

# For compatibility, maintain a flat set of all banned functions
BANNED_FUNCTIONS: set[str] = {
    func for funcs in BANNED_FUNCTIONS_CATEGORIZED.values() for func in funcs
}


def get_category_for_function(func_name: str) -> str | None:
    """
    Get the category for a given banned function name.

    Args:
        func_name: The name of the function to look up.

    Returns:
        The category name if found, None otherwise.

    Examples:
        >>> get_category_for_function("strcpy")
        'string_copy'
        >>> get_category_for_function("malloc")
        'memory'
        >>> get_category_for_function("unknown_func")
        None
    """
    for category, funcs in BANNED_FUNCTIONS_CATEGORIZED.items():
        if func_name in funcs:
            return category
    return None


def get_banned_functions_set(config: Any = None) -> set[str]:
    """
    Get the set of banned functions from config or defaults.

    This is the canonical implementation used throughout the codebase
    for obtaining the set of banned function names.

    Args:
        config: Configuration repository instance. If None, uses BANNED_FUNCTIONS.
            If config has a 'banned_functions' key, those will be used instead.

    Returns:
        A set of banned function names.

    Examples:
        >>> banned = get_banned_functions_set()
        >>> "strcpy" in banned
        True
        >>> "malloc" in banned
        True
    """
    if config is None:
        return BANNED_FUNCTIONS.copy()

    # Config may provide custom banned functions list
    banned_functions_list = config.get("banned_functions") if hasattr(config, 'get') else None
    if banned_functions_list:
        return set(banned_functions_list)

    return BANNED_FUNCTIONS.copy()
