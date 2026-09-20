"""Build garak's REST generator config from a recon Target (TOOL_API.md §2).

The request body + response extractor are derived from the endpoint's API family
(inferred from path, falling back to ai_interface_type) — the §2.3 payoff: the
attack tool is pre-configured from the graph.
"""
from __future__ import annotations

import os

# Cap every victim response. Without a bound, a tiny model under a DAN/jailbreak
# prompt rambles for thousands of tokens, each generation blows past the REST
# request_timeout (60s on CPU), every request 500s, and after enough consecutive
# failures garak's REST generator gives up and the whole run crashes mid-probe.
# A bounded reply is also faster and is plenty of signal for attack detection.
RESPONSE_MAX_TOKENS = int(os.environ.get("AI_ATTACK_RESPONSE_MAX_TOKENS", "512"))


def _family_from_target(target) -> str:
    """Infer the API family from the endpoint path (most reliable signal)."""
    path = (getattr(target, "path", "") or "").lower()
    if "/v1/chat/completions" in path:
        return "openai-chat"
    if "/v1/completions" in path:
        return "openai-completion"
    if "/v1/messages" in path:
        return "anthropic"
    if "/api/chat" in path:
        return "ollama-chat"
    if "/api/generate" in path:
        return "ollama-generate"
    # Fall back to the recon interface type.
    iface = (getattr(target, "ai_interface_type", "") or "").lower()
    if iface == "llm-completion":
        return "openai-completion"
    return "openai-chat"  # the common default


def _body_and_field(family: str, model: str):
    """Return (req_template_json_object, response_json_field) for a family."""
    if family == "openai-chat":
        return ({"model": model, "max_tokens": RESPONSE_MAX_TOKENS,
                 "messages": [{"role": "user", "content": "$INPUT"}]},
                "$.choices[0].message.content")
    if family == "openai-completion":
        return ({"model": model, "max_tokens": RESPONSE_MAX_TOKENS, "prompt": "$INPUT"},
                "$.choices[0].text")
    if family == "anthropic":
        return ({"model": model, "max_tokens": RESPONSE_MAX_TOKENS,
                 "messages": [{"role": "user", "content": "$INPUT"}]},
                "$.content[0].text")
    if family == "ollama-chat":
        # Ollama's native /api/chat uses options.num_predict, not max_tokens.
        return ({"model": model, "messages": [{"role": "user", "content": "$INPUT"}],
                 "stream": False, "options": {"num_predict": RESPONSE_MAX_TOKENS}},
                "$.message.content")
    if family == "ollama-generate":
        return ({"model": model, "prompt": "$INPUT", "stream": False,
                 "options": {"num_predict": RESPONSE_MAX_TOKENS}},
                "$.response")
    # default openai-chat
    return ({"model": model, "max_tokens": RESPONSE_MAX_TOKENS,
             "messages": [{"role": "user", "content": "$INPUT"}]},
            "$.choices[0].message.content")


def build_rest_config(target, model: str | None = None,
                      auth_header: str | None = None,
                      auth_scheme: str | None = None) -> dict:
    """Build the {"rest": {"RestGenerator": {...}}} option-file dict.

    `model`: the target model id to send. Defaults to recon's guess; some
    servers ignore it, but OpenAI/Ollama-compat require a value.
    Target auth (shared across tools): when `auth_header` is set, the header
    carries `<scheme> $KEY` so garak injects REST_API_KEY. Examples:
      Bearer:      auth_header="Authorization", auth_scheme="Bearer" -> "Bearer $KEY"
      API key hdr: auth_header="x-api-key",     auth_scheme=""       -> "$KEY"
    Omit auth_header for unauthenticated targets.
    """
    family = _family_from_target(target)
    if not model:
        ids = getattr(target, "ai_model_ids", None)
        # recon stores a list; guard against a bare string (ids[0] would slice a
        # character) or any non-list value.
        first_id = ids[0] if isinstance(ids, list) and ids else (ids if isinstance(ids, str) else None)
        model = first_id or getattr(target, "ai_model_family_guess", None) or "default"

    body, field = _body_and_field(family, model)

    headers = {"Content-Type": "application/json"}
    if auth_header:
        headers[auth_header] = f"{auth_scheme} $KEY".strip() if auth_scheme else "$KEY"

    return {
        "rest": {
            "RestGenerator": {
                "name": f"whitehat:{getattr(target, 'baseurl', '')}{getattr(target, 'path', '')}",
                "uri": target.url,
                "method": (getattr(target, "method", "POST") or "POST").lower(),
                "headers": headers,
                "req_template_json_object": body,
                "response_json": True,
                "response_json_field": field,
                "request_timeout": 60,
            }
        }
    }
