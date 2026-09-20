"""WhiteHat AI Attack Surface scan container.

The deterministic offensive-testing layer: reads the AI surface that recon
discovered (Endpoint.ai_interface_type, injectable Parameters, MCP manifests),
runs a fixed catalog of attack tools against the selected nodes, and writes
normalized Vulnerability findings back into the graph.

See internal/ADVERSARIAL_AI/AI_ATTACK_SURFACE_IMPLEMENTATION.md.

This package is the shared spine (§6): target loader, safety/bounds, normalizer.
Per-tool adapters (garak, PyRIT, giskard, promptfoo) plug in on top in later
steps. Step 2 ships the spine only, with a hardcoded dummy finding to prove the
graph-in / findings-out loop end to end.
"""
