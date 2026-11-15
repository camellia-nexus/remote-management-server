"""Unit and contract tests for Batch 84 Supply Chain Provenance (PROV-007):

Verifies that the build-web-client action strictly requires:
1. Pinned endpoint: repos/$REPOSITORY/actions/workflows/ci.yml/runs
2. Event: push
3. Branch: default_branch
4. Workflow path: .github/workflows/ci.yml
5. Successful CI / Required conclusion
"""

import unittest
from pathlib import Path

MANAGEMENT_ROOT = Path(__file__).resolve().parents[1]
ACTION_YML = MANAGEMENT_ROOT / ".github" / "actions" / "build-web-client" / "action.yml"


class TestBatch84Prov007WebClientProvenance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.content = ACTION_YML.read_text(encoding="utf-8")

    def test_prov007_queries_specific_ci_workflow_endpoint(self):
        """PROV-007: Must query actions/workflows/ci.yml/runs instead of repository-wide actions/runs."""
        self.assertIn(
            "repos/$REPOSITORY/actions/workflows/ci.yml/runs",
            self.content,
            "PROV-007 violation: action.yml must query actions/workflows/ci.yml/runs endpoint",
        )

    def test_prov007_enforces_default_branch_parameter(self):
        """PROV-007: Must filter runs by default_branch."""
        self.assertIn(
            '-f branch="$default_branch"',
            self.content,
            'PROV-007 violation: action.yml must filter by branch="$default_branch"',
        )

    def test_prov007_validates_run_path_and_branch_in_detail(self):
        """PROV-007: Must inspect individual run details to confirm path and branch match exactly."""
        self.assertIn(
            'run_path="$(jq -r \'.path // ""\' <<< "$run_detail")',
            self.content,
            "PROV-007 violation: action.yml must verify run path from run_detail",
        )
        self.assertIn(
            'run_branch="$(jq -r \'.head_branch // ""\' <<< "$run_detail")',
            self.content,
            "PROV-007 violation: action.yml must verify run head_branch from run_detail",
        )
        self.assertIn(
            'if [[ "$run_path" != ".github/workflows/ci.yml" || "$run_branch" != "$default_branch" ]]; then',
            self.content,
            "PROV-007 violation: action.yml must skip runs where path != .github/workflows/ci.yml or branch != default_branch",
        )

    def test_prov007_requires_ci_required_success(self):
        """PROV-007: Must verify CI / Required job conclusion is success."""
        self.assertIn(
            '.jobs[] | select(.name == "CI / Required" and .conclusion == "success")',
            self.content,
            "PROV-007 violation: action.yml must assert CI / Required job succeeded",
        )


if __name__ == "__main__":
    unittest.main()
