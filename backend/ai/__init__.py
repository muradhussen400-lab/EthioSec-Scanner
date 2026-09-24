"""
EthioSec AI Package.
Exposes core AI assistant capabilities, prompt builders, and context constructors.
"""

from .service import ask_ai, set_mock_provider
from .context import build_finding_context, build_scan_summary_context, build_general_context

__all__ = [
    "ask_ai",
    "set_mock_provider",
    "get_api_key",
    "build_finding_context",
    "build_scan_summary_context",
    "build_general_context",
]
