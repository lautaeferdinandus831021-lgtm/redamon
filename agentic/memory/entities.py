"""Entity extraction: the nodes of the memory knowledge graph.

agentmemory keeps a structural graph beside the text so a question can reach a
memory that shares no words with it. RedAmon's equivalent node set is small and
fact-shaped - hosts, IPs, ports, URLs, HTTP statuses, tool names, CVE ids - and
is extracted with regexes rather than an NER model, because a model would mean a
new dependency in a baked image and a per-call latency on the agent's path.

Entities are deliberately NON-SECRET: no header values, no cookies, no tokens.
An entity string is injected back into prompts and used as a join key, so
anything credential-shaped must not become one.
"""
from __future__ import annotations

import re
from typing import Iterable

_MAX_ENTITIES = 12

_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Hostnames only when they look like targets: require a dot and a TLD-ish label,
# and never a bare word, or every sentence's "config.yaml" becomes an entity.
_RE_HOST = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
_RE_URL = re.compile(r"\bhttps?://[^\s\"'<>]{3,120}", re.I)
_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_RE_PORT = re.compile(r"\b(?:port\s+|:)(\d{2,5})\b", re.I)
_RE_STATUS = re.compile(r"\bHTTP/\d(?:\.\d)?\s+(\d{3})\b")

# Tool names the agent actually calls. Restricted to a known set so a random
# capitalized word is not mistaken for one.
_KNOWN_TOOLS = (
    "nmap", "naabu", "nuclei", "httpx", "katana", "ffuf", "subfinder", "amass",
    "gau", "arjun", "wpscan", "sqlmap", "dalfox", "hydra", "metasploit",
    "curl", "playwright", "shodan", "proxy_brain", "kali_shell",
)

# File/asset suffixes that read like hostnames but are not one.
_NOT_HOST_SUFFIX = (
    ".js", ".ts", ".py", ".json", ".md", ".txt", ".yaml", ".yml", ".xml",
    ".html", ".css", ".png", ".jpg", ".log", ".csv", ".conf", ".ini", ".sh",
)


def extract_entities(text: str, *, extra: Iterable[str] = ()) -> tuple[str, ...]:
    """Pull graph entities out of a memory's text, deduped, stable-ordered."""
    blob = text or ""
    found: list[str] = []

    for match in _RE_URL.findall(blob)[:4]:
        found.append(match.rstrip(".,;)"))
    for match in _RE_CVE.findall(blob)[:4]:
        found.append(match.upper())
    for match in _RE_IPV4.findall(blob)[:4]:
        found.append(match)
    for match in _RE_HOST.findall(blob)[:6]:
        low = match.lower().rstrip(".")
        if low.endswith(_NOT_HOST_SUFFIX):
            continue
        found.append(low)

    lowered = blob.lower()
    for tool in _KNOWN_TOOLS:
        if re.search(rf"\b{re.escape(tool)}\b", lowered):
            found.append(tool)
    for match in _RE_PORT.findall(blob)[:4]:
        found.append(f"port:{match}")
    for match in _RE_STATUS.findall(blob)[:3]:
        found.append(f"http:{match}")
    for item in extra:
        s = str(item).strip()
        if s:
            found.append(s)

    out: list[str] = []
    for item in found:
        if len(item) > 120:
            continue
        if item not in out:
            out.append(item)
        if len(out) >= _MAX_ENTITIES:
            break
    return tuple(out)


def shared_entities(a: Iterable[str], b: Iterable[str]) -> int:
    return len({x.lower() for x in a} & {y.lower() for y in b})
