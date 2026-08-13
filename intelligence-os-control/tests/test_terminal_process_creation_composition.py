from __future__ import annotations

import ast
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
CONTROL_ROOT = ROOT.parent
SOURCE_PATH = CONTROL_ROOT / "verify_terminal_candidate_authority.py"


class ContractError(AssertionError):
    pass


def _function(tree: ast.Module, name: str) -> ast.FunctionDef:
    matches = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    if len(matches) != 1:
        raise ContractError(f"{name} must have exactly one top-level definition")
    return matches[0]


def _dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return None


def _calls(function: ast.FunctionDef, name: str) -> list[ast.Call]:
    return [
        node for node in ast.walk(function)
        if isinstance(node, ast.Call) and _dotted(node.func) == name
    ]


def _assigned_value(function: ast.FunctionDef, name: str) -> ast.AST:
    matches: list[ast.AST] = []
    for node in ast.walk(function):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == name
        ):
            matches.append(node.value)
    if len(matches) != 1:
        raise ContractError(f"{name} must have exactly one assignment")
    return matches[0]


class TerminalProcessCreationCompositionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = SOURCE_PATH.read_text(encoding="utf-8")
        self.tree = ast.parse(self.source)
        self.diagnostic = _function(self.tree, "_verify_terminal_bundle_diagnostic")

    def test_process_creation_proof_encloses_candidate_diagnostics_on_one_path(self) -> None:
        process_calls = _calls(self.diagnostic, "process_creation.verify")
        authenticated_calls = _calls(
            self.diagnostic, "authenticated.verify_authenticated_bundle"
        )
        nested_calls = _calls(self.diagnostic, "nested.verify")

        self.assertEqual(len(process_calls), 2)
        self.assertEqual(len(authenticated_calls), 1)
        self.assertEqual(len(nested_calls), 1)
        self.assertLess(process_calls[0].lineno, authenticated_calls[0].lineno)
        self.assertLess(process_calls[0].lineno, nested_calls[0].lineno)
        self.assertGreater(process_calls[1].lineno, nested_calls[0].lineno)

    def test_process_creation_validation_is_part_of_diagnostic_pass(self) -> None:
        value = _assigned_value(self.diagnostic, "diagnostic_passed")
        process_pass_refs = [
            node for node in ast.walk(value)
            if isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id == "process_before"
            and isinstance(node.slice, ast.Constant)
            and node.slice.value == "passed"
        ]
        self.assertEqual(len(process_pass_refs), 1)

    def test_process_creation_report_is_revalidated_after_candidate_execution(self) -> None:
        process_calls = _calls(self.diagnostic, "process_creation.verify")
        validators = _calls(self.diagnostic, "_validate_process_creation_report")
        self.assertEqual(len(process_calls), 2)
        self.assertEqual(len(validators), 2)
        self.assertLess(process_calls[0].lineno, validators[0].lineno)
        self.assertLess(process_calls[1].lineno, validators[1].lineno)

        drift_errors = [
            node for node in ast.walk(self.diagnostic)
            if isinstance(node, ast.Constant)
            and node.value == (
                "terminal-attestation process-creation authority changed during terminal verification"
            )
        ]
        self.assertEqual(len(drift_errors), 1)

    def test_no_legacy_terminal_composition_surface_remains(self) -> None:
        self.assertNotIn("verify_terminal_candidate_authority_legacy", self.source)
        self.assertNotIn("_legacy", self.source)
        self.assertFalse(
            (CONTROL_ROOT / "verify_terminal_candidate_authority_legacy.py").exists()
        )


if __name__ == "__main__":
    unittest.main()
