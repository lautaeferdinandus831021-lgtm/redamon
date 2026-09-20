"""giskard runner — runs the LLM scan and writes a results JSON.

Runs in /opt/venv-giskard (isolated). SELF-CONTAINED: giskard + pandas + stdlib,
no spine imports. See adapters/giskard/TOOL_API.md (giskard 2.19.1).

THE EGRESS FIX (§1): the scan's judge + embedding LLM are forced to the local
Ollama via LiteLLM ("ollama/<model>"), and OPENAI_API_KEY is never set — so a
mis-route fails rather than egressing to api.openai.com.
"""
import json
import sys
import urllib.request


def _family(path, interface_type):
    p = (path or "").lower()
    if "/v1/completions" in p:
        return "openai-completion"
    if "/v1/messages" in p:
        return "anthropic"
    if "/api/chat" in p:
        return "ollama-chat"
    if "/api/generate" in p:
        return "ollama-generate"
    return "openai-chat"


def _body_and_path(family, model, question):
    if family == "openai-completion":
        return {"model": model, "prompt": question}, ["choices", 0, "text"]
    if family == "anthropic":
        return ({"model": model, "max_tokens": 512, "messages": [{"role": "user", "content": question}]},
                ["content", 0, "text"])
    if family == "ollama-chat":
        return {"model": model, "messages": [{"role": "user", "content": question}], "stream": False}, ["message", "content"]
    if family == "ollama-generate":
        return {"model": model, "prompt": question, "stream": False}, ["response"]
    return {"model": model, "messages": [{"role": "user", "content": question}]}, ["choices", 0, "message", "content"]


def _make_call_target(cfg):
    headers = {"Content-Type": "application/json"}
    if cfg.get("auth_header") and cfg.get("api_key"):
        scheme = cfg.get("auth_scheme") or ""
        headers[cfg["auth_header"]] = f"{scheme} {cfg['api_key']}".strip() if scheme else cfg["api_key"]
    url = cfg["baseurl"].rstrip("/") + (cfg.get("path") or "/")
    family = _family(cfg.get("path"), cfg.get("interface_type"))
    model = cfg.get("model") or "default"

    def call(question: str) -> str:
        body, resp_path = _body_and_path(family, model, question)
        req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"),
                                     headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                obj = json.loads(r.read().decode("utf-8"))
            for k in resp_path:
                obj = obj[k]
            return obj if isinstance(obj, str) else json.dumps(obj)
        except Exception as e:
            return f"[target error: {e}]"

    return call


def main():
    import pandas as pd
    import giskard

    cfg = json.load(open(sys.argv[1]))

    # --- egress fix: judge + embedding -> local Ollama (no OPENAI_API_KEY) ---
    api_base = cfg["judge_base_url"].rstrip("/")
    giskard.llm.set_llm_model(f"ollama/{cfg['judge_model']}",
                              disable_structured_output=True, api_base=api_base)
    try:
        giskard.llm.set_embedding_model(
            f"ollama/{cfg.get('embedding_model', 'nomic-embed-text')}", api_base=api_base)
    except Exception as e:
        print(f"[giskard_run] embedding model not set ({e}); embedding detectors may skip")

    call = _make_call_target(cfg)

    def predict(df: "pd.DataFrame"):
        return [call(q) for q in df["question"].values]

    model = giskard.Model(
        model=predict, model_type="text_generation", name="whitehat-target",
        description=cfg.get("description", "A general-purpose LLM chat assistant."),
        feature_names=["question"])

    report = giskard.scan(model, only=cfg["detectors"], raise_exceptions=False,
                          max_issues_per_detector=15)

    issues = []
    for issue in report.issues:
        sev = "major" if issue.is_major else ("medium" if issue.is_medium else "minor")
        try:
            n = len(issue.examples) if getattr(issue, "examples", None) is not None else 0
        except Exception:
            n = 0
        issues.append({
            "detector": getattr(issue, "detector_name", "") or "",
            "description": str(getattr(issue, "description", "") or ""),
            "severity": sev,
            "num_examples": n,
        })

    out = {"giskard_version": giskard.__version__, "detectors": cfg["detectors"], "issues": issues}
    with open(cfg["out"], "w") as f:
        json.dump(out, f, indent=2)
    print(f"[giskard_run] {len(issues)} issue(s) -> {cfg['out']}")


if __name__ == "__main__":
    main()
