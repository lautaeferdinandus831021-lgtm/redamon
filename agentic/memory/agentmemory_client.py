"""Optional mirror to a running agentmemory server.

WHY A MIRROR, NOT A DEPENDENCY
------------------------------
RedAmon must keep working with no agentmemory server anywhere: the memory
subsystem is useful on its own (local store, tools, timeline, self-improvement),
and a hard dependency would make a scan fail because a Node service was down.
So this client is a *mirror*:

* local store = source of truth, always written first;
* agentmemory = shared second copy, so the same memories are visible to the
  other agents (Claude Code, Cursor, ...) that agentmemory already wires.

Every call is best-effort and NEVER raises: a mirror failure is logged and
dropped, because "the other memory server is unreachable" is not a reason for an
agent tool call to fail.

WIRE PROTOCOL
-------------
agentmemory serves REST + MCP on `3111` (default), so the transport here is
plain HTTP JSON and the client speaks the same verbs as its tools:

    save    -> POST  {base}{save_path}     {"content": ..., "metadata": {...}}
    recall  -> GET   {base}{recall_path}   ?q=...&limit=N
    health  -> GET   {base}/health

The paths are env-configurable (`AGENTMEMORY_SAVE_PATH`,
`AGENTMEMORY_RECALL_PATH`) rather than hardcoded: agentmemory is an external,
versioned service, and a path rename upstream should be a config change on the
server host, not a RedAmon code change and redeploy of the agent image.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 5.0


def _paths() -> tuple[str, str]:
    save = os.environ.get("AGENTMEMORY_SAVE_PATH", "/memories").strip() or "/memories"
    recall = os.environ.get("AGENTMEMORY_RECALL_PATH", "/memories/search").strip() or "/memories/search"
    return save, recall


def _auth_headers() -> dict[str, str]:
    # Read at call time: the token may be injected after this module is imported.
    headers = {"Content-Type": "application/json"}
    token = os.environ.get("AGENTMEMORY_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def encode_metadata(record) -> dict[str, Any]:
    """The subset of a memory agentmemory needs to store it as its own.

    `redamon_memory_id` is the join key on the way back: a mirror round-trip
    must update the SAME local memory, never create a duplicate beside it.
    """
    return {
        "redamon_project_id": record.project_id,
        "redamon_memory_id": record.memory_id,
        "kind": record.kind,
        "confidence": round(record.confidence, 4),
        "state": record.state,
        "entities": list(record.entities),
        "tags": list(record.tags),
    }


class AgentMemoryClient:
    """Best-effort REST client for an agentmemory server. Never raises."""

    def __init__(self, base_url: str, *, timeout: float = DEFAULT_TIMEOUT):
        self.base_url = (base_url or "").strip().rstrip("/")
        self.timeout = timeout

    @property
    def enabled(self) -> bool:
        return bool(self.base_url)

    async def health(self) -> Optional[dict[str, Any]]:
        return await self._request("GET", "/health")

    async def save(self, *, text: str, metadata: Optional[dict[str, Any]] = None) -> bool:
        save_path, _ = _paths()
        body = {"content": text, "metadata": metadata or {}}
        result = await self._request("POST", save_path, json_body=body)
        return result is not None

    async def recall(
        self,
        query: str,
        *,
        limit: int = 8,
        timeout: Optional[float] = None,
    ) -> list[dict[str, Any]]:
        _, recall_path = _paths()
        result = await self._request(
            "GET", recall_path, params={"q": query, "limit": int(limit)}, timeout=timeout,
        )
        return _as_result_list(result)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[dict[str, Any]] = None,
        params: Optional[dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        if not self.enabled:
            return None
        url = f"{self.base_url}{path}"
        try:
            async with httpx.AsyncClient(timeout=timeout or self.timeout) as client:
                resp = await client.request(
                    method, url, headers=_auth_headers(), json=json_body, params=params,
                )
            if resp.status_code >= 400:
                logger.warning(f"agentmemory mirror {method} {path} -> HTTP {resp.status_code}")
                return None
            try:
                return resp.json()
            except ValueError:
                return {}
        except Exception as e:  # noqa: BLE001 - transport, DNS, timeout, TLS
            logger.warning(f"agentmemory mirror {method} {path} failed: {e}")
            return None


def _as_result_list(payload: Any) -> list[dict[str, Any]]:
    """Normalize a recall response into a list of dicts.

    Servers differ on envelope (`[...]` vs `{"results": [...]}` vs
    `{"memories": [...]}`), and a wrong guess here would silently import
    nothing, so all three shapes are accepted and anything else is dropped.
    """
    if payload is None:
        return []
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("results", "memories", "data", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        # A single memory returned as a bare object.
        for key in ("content", "text", "memory"):
            if isinstance(payload.get(key), str):
                return [payload]
    return []


_client: Optional[AgentMemoryClient] = None
_client_url: str = ""


def get_client(base_url: str) -> Optional[AgentMemoryClient]:
    """Process-wide client for `base_url`, or None when no URL is configured."""
    global _client, _client_url
    if not (base_url or "").strip():
        return None
    url = base_url.strip().rstrip("/")
    if _client is None or _client_url != url:
        _client = AgentMemoryClient(url)
        _client_url = url
    return _client
