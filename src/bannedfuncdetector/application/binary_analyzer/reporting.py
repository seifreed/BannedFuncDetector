"""Report creation and persistence for binary analysis."""

import os
import json
import html
import logging
from datetime import datetime

from bannedfuncdetector.domain import AnalysisResult, BannedFunction, FunctionDescriptor
from bannedfuncdetector.application.dto_mappers import detection_entity_from_dto
from bannedfuncdetector.application.result_serializers import analysis_result_to_dict

logger = logging.getLogger(__name__)

# Map an output format to its file extension. Anything else falls back to JSON.
_FORMAT_EXTENSIONS = {"json": "json", "text": "txt", "html": "html"}


def _create_analysis_report(
    binary_path: str,
    functions: list[FunctionDescriptor],
    detected: list[BannedFunction],
) -> AnalysisResult:
    """Build the analysis aggregate for one binary."""
    findings = tuple(
        (
            finding
            if isinstance(finding, BannedFunction)
            else detection_entity_from_dto(finding)
        )
        for finding in detected
    )
    return AnalysisResult(
        file_name=os.path.basename(binary_path),
        file_path=os.path.abspath(binary_path),
        total_functions=len(functions),
        detected_functions=findings,
        analysis_date=datetime.now().isoformat(),
    )


def _render_json(report: AnalysisResult) -> str:
    """Render a report as pretty-printed JSON."""
    return json.dumps(analysis_result_to_dict(report), indent=4)


def _render_text(report: AnalysisResult) -> str:
    """Render a report as a plain-text summary."""
    lines = [
        f"Banned function report for {report.file_name}",
        f"Path: {report.file_path}",
        f"Date: {report.analysis_date}",
        f"Functions analyzed: {report.total_functions}",
        f"Insecure functions found: {report.insecure_count}",
        "",
    ]
    for finding in report.detected_functions:
        calls = ", ".join(finding.banned_calls)
        lines.append(
            f"  {finding.name} @ {hex(finding.address)} "
            f"[{finding.category or 'uncategorized'}] -> {calls}"
        )
    return "\n".join(lines) + "\n"


def _render_html(report: AnalysisResult) -> str:
    """Render a report as a self-contained HTML document."""
    esc = html.escape
    rows = "".join(
        "<tr>"
        f"<td>{esc(finding.name)}</td>"
        f"<td>{hex(finding.address)}</td>"
        f"<td>{esc(finding.category or 'uncategorized')}</td>"
        f"<td>{esc(', '.join(finding.banned_calls))}</td>"
        "</tr>"
        for finding in report.detected_functions
    )
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>Banned functions: {esc(report.file_name)}</title></head><body>"
        f"<h1>Banned function report</h1>"
        f"<p><strong>File:</strong> {esc(report.file_name)} "
        f"({esc(report.file_path)})</p>"
        f"<p><strong>Date:</strong> {esc(report.analysis_date)}</p>"
        f"<p><strong>Functions analyzed:</strong> {report.total_functions} "
        f"&mdash; <strong>insecure:</strong> {report.insecure_count}</p>"
        "<table border='1'><tr><th>Function</th><th>Address</th>"
        "<th>Category</th><th>Banned calls</th></tr>"
        f"{rows}</table></body></html>\n"
    )


_RENDERERS = {"json": _render_json, "text": _render_text, "html": _render_html}


def results_file_path(
    output_dir: str, binary_path: str, output_format: str = "json"
) -> str:
    """Path of the saved report for one binary.

    Shared by the writer and the optional ``open_results`` step so both agree on
    where the report lands. An unrecognized format falls back to JSON.
    """
    fmt = output_format if output_format in _RENDERERS else "json"
    extension = _FORMAT_EXTENSIONS[fmt]
    return os.path.join(
        output_dir, f"{os.path.basename(binary_path)}_banned_functions.{extension}"
    )


def _save_analysis_results(
    report: AnalysisResult,
    output_dir: str,
    binary_path: str,
    verbose: bool = False,
    output_format: str = "json",
) -> str:
    """Save one analysis aggregate in the configured format and return its path.

    Supports ``json`` (default), ``text`` and ``html``; an unrecognized format
    falls back to JSON.
    """
    fmt = output_format if output_format in _RENDERERS else "json"
    os.makedirs(output_dir, exist_ok=True)
    output_file = results_file_path(output_dir, binary_path, output_format)

    with open(output_file, "w", encoding="utf-8") as handle:
        handle.write(_RENDERERS[fmt](report))

    if verbose:
        logger.info(f"Results saved to {output_file}")

    return output_file


__all__: list[str] = []  # internal module; use explicit imports
