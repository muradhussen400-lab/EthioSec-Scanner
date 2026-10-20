"""
EthioSec AI Package.
Exposes core AI assistant capabilities, prompt builders, and context constructors.
"""

from .service import ask_ai, set_mock_provider
from .context import build_finding_context, build_scan_summary_context, build_general_context
from .executive_summary import (
    aggregate_finding_counts,
    generate_executive_summary,
    format_executive_summary_markdown,
    map_finding_to_category,
    build_deterministic_executive_summary,
)

__all__ = [
    "ask_ai",
    "set_mock_provider",
    "build_finding_context",
    "build_scan_summary_context",
    "build_general_context",
    "aggregate_finding_counts",
    "generate_executive_summary",
    "format_executive_summary_markdown",
    "map_finding_to_category",
    "build_deterministic_executive_summary",
]
