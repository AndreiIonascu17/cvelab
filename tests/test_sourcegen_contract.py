from __future__ import annotations

import unittest

from cvelab.sourcegen import (
    _canonicalize_validator_dockerfile,
    _validate_fidelity,
    _validate_generated,
    _validate_support_services,
)


def generated_files(validator: str) -> list[dict[str, str]]:
    return [
        {
            "path": "docker-compose.yml",
            "content": """services:
  vulnerable:
    build:
      context: .
      dockerfile: vulnerable/Dockerfile
  patched:
    build:
      context: .
      dockerfile: patched/Dockerfile
  validator:
    build:
      context: ./validator
      dockerfile: Dockerfile
networks:
  labnet:
    internal: true
""",
        },
        {"path": "vulnerable/Dockerfile", "content": "FROM scratch\n"},
        {"path": "patched/Dockerfile", "content": "FROM scratch\n"},
        {"path": "validator/Dockerfile", "content": "FROM scratch\n"},
        {"path": "validator/validator.py", "content": validator},
    ]


class GeneratedValidatorContractTests(unittest.TestCase):
    def test_validator_copy_is_made_relative_to_isolated_context(self) -> None:
        dockerfile = "FROM python:3.13-alpine\nCOPY validator/validator.py /validator/validator.py\n"
        normalized = _canonicalize_validator_dockerfile(dockerfile)
        self.assertIn("COPY validator.py /validator/validator.py", normalized)

    def test_manual_contract_is_required(self) -> None:
        validator = " ".join([
            "attack_executed", "proof_quality", "observable_effect", "evidence_type",
            "vulnerable", "patched", "differential_confirmed", "confirmed", "blocked",
        ])
        with self.assertRaisesRegex(RuntimeError, "manual PoC contract"):
            _validate_generated(generated_files(validator))

    def test_manual_contract_is_accepted(self) -> None:
        validator = " ".join([
            "attack_executed", "proof_quality", "observable_effect", "evidence_type",
            "vulnerable", "patched", "differential_confirmed", "confirmed", "blocked",
            "CVELAB_MANUAL_ACTION", "CVELAB_TARGET", "exploit", "verify",
        ])
        _validate_generated(generated_files(validator))

    def test_fidelity_cannot_promote_component_adapter_to_product(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "cannot claim"):
            _validate_fidelity({
                "execution_level": "source_component",
                "vendor_product_started": True,
                "exercised_vendor_components": ["parser"],
                "simulated_components": ["server"],
            })

    def test_vendor_service_fidelity_is_accepted_when_product_starts(self) -> None:
        _validate_fidelity({
            "execution_level": "vendor_service",
            "vendor_product_started": True,
            "exercised_vendor_components": ["vendor server"],
            "simulated_components": ["local backend"],
        })

    def test_product_end_to_end_requires_product_to_start(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "requires the actual vendor product"):
            _validate_fidelity({
                "execution_level": "product_end_to_end",
                "vendor_product_started": False,
                "exercised_vendor_components": ["request path"],
                "simulated_components": [],
            })

    def test_support_services_must_exist_in_compose(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "support service is missing"):
            _validate_support_services(["upstream"], "services:\n  vulnerable:\n")

        _validate_support_services(
            ["upstream"],
            "services:\n  upstream:\n    image: example.invalid/upstream\n",
        )


if __name__ == "__main__":
    unittest.main()
