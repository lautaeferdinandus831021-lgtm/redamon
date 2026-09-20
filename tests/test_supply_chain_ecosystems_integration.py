"""Cross-layer drift guard for the Supply Chain Recon ecosystem catalogue.

One list of OSV ecosystem names is duplicated in four places, in three
languages, and every copy has to agree EXACTLY (recon compares the stored value
to the harvested ecosystem with `in`, so casing is load-bearing):

  * webapp  SUPPLY_CHAIN_ECOSYSTEMS   - the multi-select the user clicks
  * python  SEED_MANIFESTS            - what ./whitehat.sh supply-chain-sync can
                                        actually populate offline
  * python  DEFAULT_SETTINGS          - the recon-side fallback
  * prisma  @default                  - what every new project gets

Nothing at runtime cross-checks them, and a mismatch is silent: the scan stays
green and simply reports nothing. Hence this test.

Run: python -m pytest tests/test_supply_chain_ecosystems_integration.py
"""

import importlib.util
import os
import re
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

_TS_CATALOGUE = os.path.join(
    _REPO, "webapp", "src", "components", "projects", "ProjectForm", "sections",
    "supplyChainEcosystems.ts")
_TS_SECTION = os.path.join(
    _REPO, "webapp", "src", "components", "projects", "ProjectForm", "sections",
    "SupplyChainReconSection.tsx")
_PRISMA = os.path.join(_REPO, "webapp", "prisma", "schema.prisma")
_HARVEST = os.path.join(_REPO, "recon", "helpers", "supply_chain", "harvest.py")


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _load_by_path(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ts_catalogue():
    """The ecosystem list out of the TypeScript module (no node needed)."""
    src = _read(_TS_CATALOGUE)
    body = re.search(r"SUPPLY_CHAIN_ECOSYSTEMS\s*=\s*\[(.*?)\]\s*as const",
                     src, re.S)
    assert body, "SUPPLY_CHAIN_ECOSYSTEMS array not found in " + _TS_CATALOGUE
    return re.findall(r"'([^']+)'", body.group(1))


class TestCatalogueDrift(unittest.TestCase):
    def test_ui_catalogue_matches_the_offline_sync_seed_manifests(self):
        from supply_chain_common.osv_db_sync import SEED_MANIFESTS
        self.assertEqual(sorted(_ts_catalogue()), sorted(SEED_MANIFESTS),
                         "the ecosystems offered in the UI and the ones "
                         "supply-chain-sync can populate have drifted")

    def test_ui_catalogue_is_not_empty(self):
        self.assertGreaterEqual(len(_ts_catalogue()), 1)

    def test_guarddog_map_only_covers_catalogue_ecosystems(self):
        scr = _load_by_path(
            "sc_recon_drift",
            os.path.join(_REPO, "recon", "main_recon_modules",
                         "supply_chain_recon.py"))
        unknown = set(scr._OSV_TO_GUARDDOG_ECO) - set(_ts_catalogue())
        self.assertEqual(unknown, set(),
                         "deep analysis maps an ecosystem the UI cannot select")


class TestDefaultsAgree(unittest.TestCase):
    def _prisma_default(self):
        match = re.search(
            r'supplyChainReconEcosystems\s+String\s+@default\("([^"]*)"\)',
            _read(_PRISMA))
        self.assertIsNotNone(match, "prisma default for the field not found")
        return match.group(1)

    def _recon_default(self):
        settings = _load_by_path(
            "recon_project_settings_drift",
            os.path.join(_REPO, "recon", "project_settings.py"))
        return settings.DEFAULT_SETTINGS["SUPPLY_CHAIN_RECON_ECOSYSTEMS"]

    def test_prisma_and_recon_defaults_are_identical(self):
        # The Prisma default reaches recon only for projects that have a row;
        # DEFAULT_SETTINGS covers CLI runs and missing fields. They must agree
        # or the same project scans differently depending on the entry point.
        self.assertEqual(self._prisma_default(), self._recon_default())

    def test_the_default_is_made_of_catalogue_names(self):
        catalogue = _ts_catalogue()
        for token in [t.strip() for t in self._prisma_default().split(",")]:
            self.assertIn(token, catalogue)

    def test_the_default_selects_the_only_harvested_ecosystem(self):
        self.assertIn("npm", self._prisma_default().split(","))


class TestHarvestedEcosystemAssumption(unittest.TestCase):
    """The UI warns "this module harvests npm packages only". That claim is a
    fact about harvest.py, so it has to be re-checked when harvest.py changes."""

    def test_harvest_only_emits_npm(self):
        emitted = set(re.findall(r'"ecosystem":\s*"([^"]+)"', _read(_HARVEST)))
        self.assertEqual(emitted, {"npm"},
                         "harvest.py now emits {} - update HARVESTED_ECOSYSTEM "
                         "and the npm-only warning in "
                         "SupplyChainReconSection.tsx".format(sorted(emitted)))

    def test_the_ui_declares_the_same_harvested_ecosystem(self):
        src = _read(_TS_CATALOGUE)
        match = re.search(r"HARVESTED_ECOSYSTEM\s*=\s*'([^']+)'", src)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "npm")

    def test_the_section_consumes_the_declared_constant(self):
        # Only that the warning is wired to HARVESTED_ECOSYSTEM rather than a
        # second hardcoded "npm" that could drift from it. Whether the widget
        # renders correctly is covered by SupplyChainReconSection.test.tsx -
        # grepping the JSX here would just be a brittle copy of that.
        self.assertIn("HARVESTED_ECOSYSTEM", _read(_TS_SECTION))


if __name__ == "__main__":
    unittest.main()
