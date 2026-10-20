"""
EthioSec Scanner AI Service Adapter.
Delegates to the central AI service in backend/ai/service.py to avoid duplicate integrations.
"""
from ai.service import ask_ai

__all__ = ["ask_ai"]
