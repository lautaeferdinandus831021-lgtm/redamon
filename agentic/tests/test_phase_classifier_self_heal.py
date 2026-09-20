"""Integration tests for the attack-path classifier's parameter self-heal.

``phase.classify_attack_path`` runs its own retry loop around a direct
``llm.ainvoke`` (it does NOT go through ``retry_llm_call``), so it needs the
shared ``heal_llm_param_error`` wired in explicitly. Without it, selecting a
model that rejects our default ``temperature=0`` (Moonshot k3, OpenAI o-series,
Bedrock Claude 4.x, GLM/Qwen thinking, ...) made the classifier burn all 3
attempts on an identical 400 and silently fall back to the safe default
("cve_exploit"/"informational") — degrading routing quality invisibly.

These tests drive the real function with a mocked LLM and assert it heals the
param error and returns the model's actual classification.

Run (inside agent container):
    docker run --rm \\
        -v "/path/agentic:/app" \\
        -v "/path/graph_db:/app/graph_db:ro" \\
        -v "/path/knowledge_base:/app/knowledge_base:ro" \\
        -w /app whitehat-agent python -m unittest \\
        tests.test_phase_classifier_self_heal -v
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

# A valid AttackPathClassification payload the healed clone will return.
_VALID_CLASSIFICATION = MagicMock(content=(
    '{"required_phase": "exploitation", "attack_path_type": "sql_injection", '
    '"confidence": 0.9, "reasoning": "obvious SQLi objective"}'
))

_KIMI_TEMP_ERROR = (
    "Error code: 400 - {'error': {'message': 'invalid temperature: only 1 is "
    "allowed for this model', 'type': 'invalid_request_error'}}"
)
_OPENAI_TEMP_ERROR = (
    "Unsupported value: 'temperature' does not support 0 with this model. "
    "Only the default (1) value is supported."
)
_GLM_TEMP_ERROR = (
    "Error code: 400 - temperature must be greater than 0 and less than or "
    "equal to 1"
)


class PhaseClassifierSelfHealTests(unittest.IsolatedAsyncioTestCase):

    async def _classify(self, mock_llm):
        from orchestrator_helpers.phase import classify_attack_path
        with patch(
            "orchestrator_helpers.phase.asyncio.sleep", new_callable=AsyncMock,
        ):
            return await classify_attack_path(mock_llm, "dump the users table via SQLi")

    def _healable(self, *, error_str):
        healed = MagicMock()
        healed.ainvoke = AsyncMock(return_value=_VALID_CLASSIFICATION)
        llm = MagicMock()
        llm.ainvoke = AsyncMock(side_effect=Exception(error_str))
        llm.model_copy = MagicMock(return_value=healed)
        return llm, healed

    async def test_kimi_temperature_error_heals_and_classifies(self):
        llm, healed = self._healable(error_str=_KIMI_TEMP_ERROR)
        attack_type, phase, host, port, cves = await self._classify(llm)
        # The MODEL's classification wins — NOT the safe cve_exploit fallback.
        self.assertEqual(attack_type, "sql_injection")
        self.assertEqual(phase, "exploitation")
        self.assertEqual(llm.ainvoke.await_count, 1)
        self.assertEqual(healed.ainvoke.await_count, 1)
        llm.model_copy.assert_called_once_with(update={"temperature": None})

    async def test_openai_o_series_error_heals(self):
        llm, healed = self._healable(error_str=_OPENAI_TEMP_ERROR)
        attack_type, phase, *_ = await self._classify(llm)
        self.assertEqual(attack_type, "sql_injection")
        llm.model_copy.assert_called_once_with(update={"temperature": None})

    async def test_glm_range_error_heals(self):
        llm, healed = self._healable(error_str=_GLM_TEMP_ERROR)
        attack_type, phase, *_ = await self._classify(llm)
        self.assertEqual(attack_type, "sql_injection")
        llm.model_copy.assert_called_once_with(update={"temperature": None})

    async def test_permanent_non_param_error_falls_back_safely(self):
        """A genuine non-recoverable error (bad API key) must NOT be mistaken
        for a param error: no heal, attempts exhaust, safe default returned."""
        llm = MagicMock()
        llm.ainvoke = AsyncMock(side_effect=Exception("Error code: 401 - invalid api key"))
        llm.model_copy = MagicMock()
        attack_type, phase, host, port, cves = await self._classify(llm)
        self.assertEqual(attack_type, "cve_exploit")   # safe fallback
        self.assertEqual(phase, "informational")
        llm.model_copy.assert_not_called()
        # No heal → all 3 attempts consumed on the real error.
        self.assertEqual(llm.ainvoke.await_count, 3)


if __name__ == "__main__":
    unittest.main()
