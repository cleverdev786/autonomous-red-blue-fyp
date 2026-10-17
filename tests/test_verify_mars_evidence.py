import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import verify_mars_evidence as review


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    return hashlib.sha256(value).hexdigest()


def structured(path, obj):
    return save(path, (json.dumps(obj, sort_keys=True) + "\n").encode())


class TestArchiveInvariants(unittest.TestCase):
    def test_archive_inventory_detects_changed_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp).absolute()
            old = save(parent / "file.json", b"original")
            self.assertEqual(review.verify_indexed_files(parent, {"file.json": old}), 1)
            save(parent / "file.json", b"tampered")
            with self.assertRaises(review.EvidenceMismatch):
                review.verify_indexed_files(parent, {"file.json": old})

    def test_relative_paths_cannot_escape_evidence_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).absolute()
            for candidate in ("../secret", "/tmp/secret", "a/../file", "./file"):
                with self.subTest(candidate=candidate), self.assertRaises(review.EvidenceMismatch):
                    review.child_file(base, candidate)

    def test_symlinked_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).absolute()
            target = base / "target"
            target.write_text("evidence")
            symlink = base / "link"
            symlink.symlink_to(target)
            with self.assertRaises(review.EvidenceMismatch):
                review.sha256(symlink)

    def test_original_negative_model_result_and_trusted_patch_are_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).absolute()
            indexdir = root / "mars-nonsql-live-20261017-v1"
            indexdir.mkdir()
            model = root / "capability-evidence"
            cases = []
            inventory = {}
            for case in ("xss", "traversal"):
                archive = model / f"probe-{case}"
                archive.mkdir(parents=True)
                checks = {
                    "q8-nonsql-raw.json": structured(
                        archive / "q8-nonsql-raw.json", {"content": "wrong line"}
                    )
                }
                replay = {
                    "status": "passed",
                    "docker_replayed": True,
                    "model_authored_patch": False,
                    "final_research_qualified": False,
                    "registered_exploit_evidence": [],
                    "functional_checks": {"normal": True},
                }
                receipt_name = f"{case}-patched-docker-receipt.json"
                sha = structured(indexdir / receipt_name, replay)
                inventory[receipt_name] = sha
                cases.append(
                    {
                        "scenario": case,
                        "model_archived": str(archive),
                        "model_files_sha256": checks,
                        "real_red_exploit_confirmed": True,
                        "source_localization_accepted": False,
                        "trusted_deterministic_patched_docker_passed": True,
                        "trusted_deterministic_patched_docker_receipt_sha256": sha,
                        "model_authored_patch": False,
                        "model_intent_status": "outcome_unknown",
                    }
                )
            index = {
                "scenarios": cases,
                "external_file_sha256": inventory,
                "final_research_qualified": False,
                "model_authored_patch": False,
            }
            fixed = structured(indexdir / "outcome.json", index)
            with patch.object(review, "BASELINE_SHA", fixed):
                self.assertEqual(
                    review.verify_original(indexdir)["trusted_docker_replays_passed"], 2
                )
                cases[0]["source_localization_accepted"] = True
                changed = structured(indexdir / "outcome.json", index)
                with (
                    patch.object(review, "BASELINE_SHA", changed),
                    self.assertRaises(review.EvidenceMismatch),
                ):
                    review.verify_original(indexdir)

    def test_retrospective_rejects_qualification_promotion(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp).absolute()
            rows = []
            for case in ("xss", "traversal"):
                folder = directory / case
                raw = {
                    "status": "rejected",
                    "qualified": False,
                    "model_repair_authority": False,
                    "raw_selected": {"sink_line": 85 if case == "xss" else 108},
                }
                digest = structured(folder / "outcome.json", raw)
                rows.append(
                    {
                        "scenario": case,
                        "directory": str(folder),
                        "status": "rejected",
                        "old_model_receipt_untouched": True,
                        "raw_selected_line": raw["raw_selected"]["sink_line"],
                        "file_sha256": {"outcome.json": digest},
                    }
                )
            index = {
                "original_evidence_sha256": review.BASELINE_SHA,
                "prospective": False,
                "model_authority": False,
                "final_research_qualified": False,
                "results": rows,
            }
            original = structured(directory / "audit.json", index)
            with patch.object(review, "DIAGNOSTIC_SHA", original):
                self.assertEqual(review.verify_diagnostic(directory)["retrospective_cases"], 2)
                structured(
                    directory / "xss" / "outcome.json",
                    {"status": "source_verified", "qualified": True},
                )
                with self.assertRaises(review.EvidenceMismatch):
                    review.verify_diagnostic(directory)


if __name__ == "__main__":
    unittest.main()
