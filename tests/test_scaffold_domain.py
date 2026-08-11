import json
import py_compile
import tempfile
import unittest
from pathlib import Path

from pydantic import ValidationError

from pipeline.scaffold_domain import load_spec, scaffold_domain


SPEC = {
    "domain_name": "LightSwitch",
    "module_name": "light_switch",
    "state_variables": [{"name": "enabled", "type": "int", "bound": [0, 1]}],
    "operations": [{
        "name": "turnOn", "guards": [], "effect": "enable",
        "frame": ["enabled"], "ast_pattern": "enabled == 1",
    }],
    "tlc_invariants": ["TypeOK"],
}


class DomainScaffolderTests(unittest.TestCase):
    def prepare(self, root: Path, value=SPEC) -> Path:
        spec = root / "domain.json"
        spec.write_text(json.dumps(value), encoding="utf-8")
        domains = root / "pipeline" / "domains"
        domains.mkdir(parents=True)
        (domains / "registry.py").write_text(
            "# BEGIN SCAFFOLDED IMPORTS\n# END SCAFFOLDED IMPORTS\n"
            "PLUGINS = [\n    # BEGIN SCAFFOLDED PLUGINS\n"
            "    # END SCAFFOLDED PLUGINS\n]\n", encoding="utf-8")
        return spec

    def test_generates_compilable_fail_closed_plugin_and_registration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outputs = scaffold_domain(self.prepare(root), project_root=root)
            self.assertEqual(len(outputs), 4)
            for output in outputs:
                py_compile.compile(str(output), doraise=True)
            extractor = (root / "pipeline/domains/light_switch_extract.py").read_text()
            self.assertIn("plugin is scaffolded but its AST adapter is not reviewed", extractor)
            registry = (root / "pipeline/domains/registry.py").read_text()
            self.assertIn("LIGHT_SWITCH_PLUGIN", registry)

    def test_refuses_to_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = self.prepare(root)
            scaffold_domain(spec, project_root=root)
            with self.assertRaises(FileExistsError):
                scaffold_domain(spec, project_root=root)

    def test_rejects_undeclared_frames_and_unsafe_module_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bad = {**SPEC, "module_name": "../../escape"}
            spec = root / "bad.json"
            spec.write_text(json.dumps(bad), encoding="utf-8")
            with self.assertRaises(ValidationError):
                load_spec(spec)
            bad = {**SPEC, "operations": [{**SPEC["operations"][0], "frame": ["secret"]}]}
            spec.write_text(json.dumps(bad), encoding="utf-8")
            with self.assertRaises(ValidationError):
                load_spec(spec)


if __name__ == "__main__":
    unittest.main()
