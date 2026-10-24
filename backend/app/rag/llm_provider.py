"""
Phase 3.5.5 — LLM Provider Abstraction Module.
Provides pluggable provider interface supporting Mock (offline/keyless) and HTTP API providers.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
import time
from typing import Optional

from app.config.settings import settings
from app.rag.context_builder import GroundedContext


@dataclass
class LLMGenerationResponse:
    answer: str
    provider: str
    model: str
    latency_ms: float
    success: bool
    error: Optional[str] = None


class BaseLLMProvider(ABC):
    """Abstract Base Class for LLM Providers."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        pass

    @abstractmethod
    def generate(self, context: GroundedContext) -> LLMGenerationResponse:
        """Generate answer from GroundedContext."""
        pass


class MockLLMProvider(BaseLLMProvider):
    """
    Deterministic Mock LLM Provider for offline development and testing.

    Operates 100% offline without network calls or external API keys.
    Extracts retrieved sources and evidence from GroundedContext to produce an
    explainable, conservative response.
    """

    def __init__(self, model: str = "mock-offline-v1"):
        self._model = model

    @property
    def provider_name(self) -> str:
        return "mock"

    @property
    def model_name(self) -> str:
        return self._model

    def generate(self, context: GroundedContext) -> LLMGenerationResponse:
        start_time = time.time()

        if not context or not context.user_question:
            return LLMGenerationResponse(
                answer="No question provided.",
                provider=self.provider_name,
                model=self.model_name,
                latency_ms=0.0,
                success=False,
                error="Empty context or question",
            )

        lines = []
        lines.append(f"Analysis for question: '{context.user_question}'")
        lines.append("")

        # Summarize retrieved knowledge sources
        if context.retrieved_items:
            lines.append("Retrieved Domain Knowledge Sources:")
            for item in context.retrieved_items:
                tech_id = f" ({item.technique_id})" if item.technique_id else ""
                cve_id = f" ({item.cve_id})" if item.cve_id else ""
                lines.append(f" - {item.title}{tech_id}{cve_id} [Source: {item.source_type} v{item.source_version}, Trust: {item.trust_level}]")
            lines.append("")

        # Static analysis capability warning
        lines.append(
            "Static Analysis Boundary Notice: Static findings represent candidate capabilities "
            "and permissions. Runtime execution was not independently established."
        )

        latency = (time.time() - start_time) * 1000.0
        return LLMGenerationResponse(
            answer="\n".join(lines),
            provider=self.provider_name,
            model=self.model_name,
            latency_ms=round(latency, 2),
            success=True,
            error=None,
        )


class OpenAILikeLLMProvider(BaseLLMProvider):
    """
    HTTP API LLM Provider for OpenAI/Gemini/Ollama compatible endpoints.
    Uses httpx for network calls. Falls back safely if API key is missing or request fails.
    """

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or settings.RAG_LLM_API_KEY
        self.model = model or settings.RAG_LLM_MODEL or "gpt-4o-mini"

    @property
    def provider_name(self) -> str:
        return "openai"

    @property
    def model_name(self) -> str:
        return self.model

    def generate(self, context: GroundedContext) -> LLMGenerationResponse:
        start_time = time.time()

        if not self.api_key or not self.api_key.strip():
            # Fall back safely if API key is unconfigured
            mock_fallback = MockLLMProvider(model=f"{self.model}-fallback")
            res = mock_fallback.generate(context)
            res.error = "API key unconfigured; offline mock provider fallback applied."
            return res

        try:
            import httpx
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": context.SYSTEM_INSTRUCTIONS},
                    {"role": "user", "content": context.full_prompt_text},
                ],
                "temperature": 0.2,
            }

            resp = httpx.post("https://api.openai.com/v1/chat/completions", json=payload, headers=headers, timeout=10.0)
            latency = (time.time() - start_time) * 1000.0

            if resp.status_code == 200:
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                return LLMGenerationResponse(
                    answer=content,
                    provider=self.provider_name,
                    model=self.model_name,
                    latency_ms=round(latency, 2),
                    success=True,
                )
            else:
                return LLMGenerationResponse(
                    answer="LLM API request failed.",
                    provider=self.provider_name,
                    model=self.model_name,
                    latency_ms=round(latency, 2),
                    success=False,
                    error=f"HTTP {resp.status_code}: {resp.text[:200]}",
                )
        except Exception as ex:
            latency = (time.time() - start_time) * 1000.0
            return LLMGenerationResponse(
                answer="LLM provider connection error.",
                provider=self.provider_name,
                model=self.model_name,
                latency_ms=round(latency, 2),
                success=False,
                error=str(ex),
            )


def get_llm_provider(provider_type: Optional[str] = None) -> BaseLLMProvider:
    """Factory function for instantiating LLM providers."""
    p_type = (provider_type or settings.RAG_LLM_PROVIDER or "mock").lower().strip()
    if p_type in ("mock", "offline", "test"):
        return MockLLMProvider()
    elif p_type in ("openai", "custom", "http"):
        return OpenAILikeLLMProvider()
    else:
        # Fall back to MockLLMProvider for safety rather than crashing
        return MockLLMProvider()
