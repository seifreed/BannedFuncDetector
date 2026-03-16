"""Typed configuration models and default values."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..constants import DEFAULT_MAX_WORKERS, DEFAULT_OUTPUT_DIR


@dataclass(frozen=True)
class DecompilerOption:
    """Configuration for a single decompiler."""

    enabled: bool = True
    command: str = ""
    description: str = ""
    ignore_unknown_branches: bool = True
    clean_error_messages: bool = True
    fallback_to_asm: bool = True
    model: str = ""
    api: str = ""
    prompt: str = ""
    host: str = ""
    port: int = 0
    server_url: str = ""
    temperature: float = 0.7
    context: int = 8192
    max_tokens: int = 4096
    system_prompt: str = ""


DEFAULT_DECOMPILER_OPTIONS: dict[str, DecompilerOption] = {
    "default": DecompilerOption(
        enabled=True,
        command="pdc",
        description="Default radare2 decompiler",
    ),
    "r2ghidra": DecompilerOption(
        enabled=True,
        command="pdg",
        description="r2ghidra decompiler",
    ),
    "r2dec": DecompilerOption(
        enabled=True,
        command="pdd",
        description="r2dec decompiler",
    ),
    "r2ai": DecompilerOption(
        enabled=True,
        command="pdai",
        description="AI-based decompiler (r2ai)",
        model="hhao/qwen2.5-coder-tools:32b",
        system_prompt=(
            "You are a reverse engineering assistant focused on decompiling "
            "assembly code into clean, human-readable C code."
        ),
    ),
    "decai": DecompilerOption(
        enabled=True,
        command="decai -d",
        description="AI-based decompiler (decai)",
        api="ollama",
        model="qwen2:5b-coder",
        prompt=(
            "Rewrite this function and respond ONLY with code, NO explanations, "
            "NO markdown, Change 'goto' into if/else/for/while, Simplify as much "
            "as possible, use better variable names, take function arguments and "
            "strings from comments like 'string:'"
        ),
        host="http://localhost",
        port=11434,
    ),
    "r2ai-server": DecompilerOption(
        enabled=True,
        command="pdai",
        description="AI-based decompiler (r2ai-server)",
        server_url="http://localhost:8080",
        model="mistral-7b-instruct-v0.2.Q2_K",
        system_prompt=(
            "You are a reverse engineering assistant focused on decompiling "
            "assembly code into clean, human-readable C code."
        ),
    ),
}


@dataclass(frozen=True)
class AppConfig:
    """Application configuration with typed defaults."""

    decompiler_type: str = "default"
    decompiler_options: dict[str, DecompilerOption] = field(
        default_factory=lambda: dict(DEFAULT_DECOMPILER_OPTIONS)
    )
    ignore_unknown_branches: bool = True
    clean_error_messages: bool = True
    fallback_to_asm: bool = True
    max_retries: int = 3
    error_threshold: float = 0.1
    use_alternative_decompiler: bool = True
    output_directory: str = DEFAULT_OUTPUT_DIR
    output_format: str = "json"
    open_results: bool = False
    verbose: bool = False
    parallel: bool = True
    max_workers: int = DEFAULT_MAX_WORKERS
    timeout: int = 600
    worker_limit: int | None = None
    skip_small_functions: bool = True
    small_function_threshold: int = 10

    def to_dict(self) -> dict[str, Any]:
        """Convert to nested dictionary for backward compatibility."""
        decompiler_options_dict: dict[str, Any] = {}
        for name, opt in self.decompiler_options.items():
            opt_dict: dict[str, Any] = {"enabled": opt.enabled}
            if opt.command:
                opt_dict["command"] = opt.command
            if opt.description:
                opt_dict["description"] = opt.description
            if opt.model:
                opt_dict["model"] = opt.model
            if opt.api:
                opt_dict["api"] = opt.api
            if opt.prompt:
                opt_dict["prompt"] = opt.prompt
            if opt.host:
                opt_dict["host"] = opt.host
            if opt.port:
                opt_dict["port"] = opt.port
            if opt.server_url:
                opt_dict["server_url"] = opt.server_url
            decompiler_options_dict[name] = opt_dict

        decompiler_options_dict["ignore_unknown_branches"] = self.ignore_unknown_branches
        decompiler_options_dict["max_retries"] = self.max_retries
        decompiler_options_dict["fallback_to_asm"] = self.fallback_to_asm
        decompiler_options_dict["error_threshold"] = self.error_threshold
        decompiler_options_dict["clean_error_messages"] = self.clean_error_messages
        decompiler_options_dict["use_alternative_decompiler"] = self.use_alternative_decompiler

        return {
            "decompiler": {
                "type": self.decompiler_type,
                "options": decompiler_options_dict,
            },
            "output": {
                "directory": self.output_directory,
                "format": self.output_format,
                "open_results": self.open_results,
                "verbose": self.verbose,
            },
            "analysis": {
                "parallel": self.parallel,
                "max_workers": self.max_workers,
                "timeout": self.timeout,
                "worker_limit": self.worker_limit,
            },
            "max_workers": self.max_workers,
            "skip_small_functions": self.skip_small_functions,
            "small_function_threshold": self.small_function_threshold,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AppConfig":
        """Create AppConfig from a dictionary."""
        decompiler_data = data.get("decompiler", {})
        options_data = decompiler_data.get("options", {})
        output_data = data.get("output", {})
        analysis_data = data.get("analysis", {})

        decompiler_options = {}
        for name, default_opt in DEFAULT_DECOMPILER_OPTIONS.items():
            opt_data = options_data.get(name, {})
            error_handling = opt_data.get("error_handling", {})
            advanced = opt_data.get("advanced_options", {})

            decompiler_options[name] = DecompilerOption(
                enabled=opt_data.get("enabled", default_opt.enabled),
                command=opt_data.get("command", default_opt.command),
                description=opt_data.get("description", default_opt.description),
                ignore_unknown_branches=error_handling.get(
                    "ignore_unknown_branches", default_opt.ignore_unknown_branches
                ),
                clean_error_messages=error_handling.get(
                    "clean_error_messages", default_opt.clean_error_messages
                ),
                fallback_to_asm=error_handling.get(
                    "fallback_to_asm", default_opt.fallback_to_asm
                ),
                model=opt_data.get("model", default_opt.model),
                api=opt_data.get("api", default_opt.api),
                prompt=opt_data.get("prompt", default_opt.prompt),
                host=opt_data.get("host", default_opt.host),
                port=opt_data.get("port", default_opt.port),
                server_url=opt_data.get("server_url", default_opt.server_url),
                temperature=advanced.get("temperature", default_opt.temperature),
                context=advanced.get("context", default_opt.context),
                max_tokens=advanced.get("max_tokens", default_opt.max_tokens),
                system_prompt=advanced.get("system_prompt", default_opt.system_prompt),
            )

        return cls(
            decompiler_type=decompiler_data.get("type", "default"),
            decompiler_options=decompiler_options,
            ignore_unknown_branches=options_data.get("ignore_unknown_branches", True),
            clean_error_messages=options_data.get("clean_error_messages", True),
            fallback_to_asm=options_data.get("fallback_to_asm", True),
            max_retries=options_data.get("max_retries", 3),
            error_threshold=options_data.get("error_threshold", 0.1),
            use_alternative_decompiler=options_data.get("use_alternative_decompiler", True),
            output_directory=output_data.get("directory", DEFAULT_OUTPUT_DIR),
            output_format=output_data.get("format", "json"),
            open_results=output_data.get("open_results", False),
            verbose=output_data.get("verbose", False),
            parallel=analysis_data.get("parallel", True),
            max_workers=analysis_data.get("max_workers", DEFAULT_MAX_WORKERS),
            timeout=analysis_data.get("timeout", 600),
            worker_limit=analysis_data.get("worker_limit"),
            skip_small_functions=data.get("skip_small_functions", True),
            small_function_threshold=data.get("small_function_threshold", 10),
        )


DEFAULT_APP_CONFIG = AppConfig()
DEFAULT_CONFIG: dict[str, Any] = DEFAULT_APP_CONFIG.to_dict()


__all__ = [
    "DecompilerOption",
    "AppConfig",
    "DEFAULT_DECOMPILER_OPTIONS",
    "DEFAULT_APP_CONFIG",
    "DEFAULT_CONFIG",
]
