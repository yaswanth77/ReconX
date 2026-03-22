"""
AI providers — OpenAI, Ollama, Groq.

Common interface for all LLM providers so the engine
doesn't care which one is backing it.
"""

from abc import ABC, abstractmethod
from typing import Optional
import json


class AIProvider(ABC):
    """Base interface for all AI providers."""

    @abstractmethod
    def complete(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float = 0.3,
        max_tokens: int = 2000,
        json_mode: bool = False,
    ) -> str:
        """Send a prompt and return the completion text."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this provider is configured and reachable."""
        ...


class OpenAIProvider(AIProvider):
    """OpenAI API provider (GPT-4o-mini for cost efficiency)."""

    def __init__(self, api_key: str, model: str = "gpt-4o-mini", base_url: str | None = None):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url

    def complete(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float = 0.3,
        max_tokens: int = 2000,
        json_mode: bool = False,
    ) -> str:
        try:
            from openai import OpenAI

            kwargs = {"api_key": self.api_key}
            if self.base_url:
                kwargs["base_url"] = self.base_url

            client = OpenAI(**kwargs)

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            create_kwargs = {
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            if json_mode:
                create_kwargs["response_format"] = {"type": "json_object"}

            response = client.chat.completions.create(**create_kwargs)
            return response.choices[0].message.content or ""
        except Exception as e:
            return f"[AI Error: {e}]"

    def is_available(self) -> bool:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=self.api_key)
            client.models.list()
            return True
        except Exception:
            return bool(self.api_key)


class OllamaProvider(AIProvider):
    """Ollama local LLM provider (free, runs locally)."""

    def __init__(self, model: str = "llama3", base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url

    def complete(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float = 0.3,
        max_tokens: int = 2000,
        json_mode: bool = False,
    ) -> str:
        try:
            import ollama

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            kwargs = {
                "model": self.model,
                "messages": messages,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            }
            if json_mode:
                kwargs["format"] = "json"

            response = ollama.chat(**kwargs)
            return response["message"]["content"] or ""
        except Exception as e:
            return f"[AI Error: {e}]"

    def is_available(self) -> bool:
        try:
            import ollama
            ollama.list()
            return True
        except Exception:
            return False


class GroqProvider(AIProvider):
    """Groq API provider (fast inference)."""

    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile"):
        self.api_key = api_key
        self.model = model

    def complete(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float = 0.3,
        max_tokens: int = 2000,
        json_mode: bool = False,
    ) -> str:
        try:
            from openai import OpenAI

            client = OpenAI(
                api_key=self.api_key,
                base_url="https://api.groq.com/openai/v1",
            )

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            create_kwargs = {
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            if json_mode:
                create_kwargs["response_format"] = {"type": "json_object"}

            response = client.chat.completions.create(**create_kwargs)
            return response.choices[0].message.content or ""
        except Exception as e:
            return f"[AI Error: {e}]"

    def is_available(self) -> bool:
        return bool(self.api_key)


def create_provider(
    provider_name: str,
    api_key: str | None = None,
    model: str | None = None,
    base_url: str | None = None,
) -> AIProvider | None:
    """Factory function to create the right provider."""
    if provider_name == "openai":
        if not api_key:
            return None
        return OpenAIProvider(api_key=api_key, model=model or "gpt-4o-mini", base_url=base_url)
    elif provider_name == "ollama":
        return OllamaProvider(model=model or "llama3", base_url=base_url or "http://localhost:11434")
    elif provider_name == "groq":
        if not api_key:
            return None
        return GroqProvider(api_key=api_key, model=model or "llama-3.3-70b-versatile")
    return None
