import ast
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "contracts" / "jury_source_guard.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)


class JurySourceGuardTests(unittest.TestCase):
    def test_append_only_receipt_api_exists(self):
        names = {node.name for node in ast.walk(TREE) if isinstance(node, ast.FunctionDef)}
        self.assertTrue({"admit_evidence", "get_receipt", "list_receipt_ids"}.issubset(names))
        self.assertIn("self.receipt_ids.append(receipt_id)", SOURCE)

    def test_validators_recompute_every_consequential_field(self):
        for field in ("decision", "claim_supported", "authority_source_count", "manipulation_signals",
                      "conflict_signals", "source_snapshot_hashes", "snapshot_bundle_hash"):
            self.assertIn(f'"{field}"', SOURCE)
        self.assertIn("gl.vm.run_nondet_unsafe", SOURCE)

    def test_full_source_provenance_and_canonical_commitments(self):
        self.assertIn("gl.nondet.web.render(url, mode=\"text\")", SOURCE)
        self.assertNotIn("[:3200]", SOURCE)
        self.assertIn("two_independent_registrable_domains_required", SOURCE)
        self.assertIn("two_authority_bound_sources_required", SOURCE)
        self.assertIn("hashlib.sha256", SOURCE)
        self.assertIn("str(len(str(part)))", SOURCE)

    def test_admit_cannot_follow_seo_or_conflicting_evidence(self):
        self.assertIn("admit_requires_clean_direct_support", SOURCE)
        self.assertIn("challenge_requires_concrete_signal", SOURCE)
        self.assertIn("SEO copy", SOURCE)


if __name__ == "__main__":
    unittest.main()
