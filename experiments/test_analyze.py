import unittest
from analyze import paired_stages, validate_security, validate_workload, MAIN_SETUPS, DEFENSE_LABEL


class EvidenceTests(unittest.TestCase):
    def test_stacked_components_preserve_paired_total(self):
        # Marginal medians sum to 200, while median latency is 110.
        row = {"latency_us": [110, 110, 210], "stages": [
            dict(auth_us=a, resolve_us=b, policy_us=0, execute_us=0,
                 audit_us=0, total_us=a+b+5)
            for a, b in [(0, 100), (100, 0), (100, 100)]]}
        values = paired_stages(row)
        self.assertAlmostEqual(sum(values), 430/3)
        self.assertEqual(values[-2:], [5, 5])

    def test_unpaired_timings_fail(self):
        with self.assertRaises(ValueError):
            paired_stages({"latency_us": [10], "stages": []})

    def test_bad_security_evidence_fails(self):
        attacks = [{"id": "example"}]
        rows = [{"setup": s, "id": "example", "outcome": "blocked"}
                for s in MAIN_SETUPS + [f"ZTAC-no-{d}" for d in DEFENSE_LABEL]]
        validate_security(rows, attacks)
        for bad in [rows[:-1], rows + [rows[0]],
                    [{**rows[0], "outcome": "invalid"}] + rows[1:]]:
            with self.assertRaises(ValueError):
                validate_security(bad, attacks)

    def test_workload_requires_equal_valid_unique_sets(self):
        rows = [{"setup": s, "id": i, "valid": True, "completed": False}
                for s in MAIN_SETUPS + [f"ZTAC-no-{d}" for d in DEFENSE_LABEL]
                for i in ["a", "b"]]
        # Legitimate failed operations stay in the denominator.
        self.assertEqual(len(validate_workload(rows, "operations")["ZTAC"]), 2)
        for bad in [rows[:-1], rows + [rows[0]],
                    [{**rows[0], "valid": False}] + rows[1:]]:
            with self.assertRaises(ValueError):
                validate_workload(bad, "operations")


if __name__ == "__main__":
    unittest.main()
