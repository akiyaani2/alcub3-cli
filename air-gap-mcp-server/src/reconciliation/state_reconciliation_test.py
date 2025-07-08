import unittest
import asyncio
import time
import logging
from datetime import datetime

# Adjust sys.path to include the project root for module discovery
import sys
sys.path.insert(0, '/Users/aaronkiyaani-mcclary/Dev IDE Projects/alcub3-cli/air-gap-mcp-server')

from src.reconciliation.state_reconciliation import (
    StateReconciliationEngine, ConflictType, ResolutionStrategy, ReconciliationStatus,
    ClassificationLevel, SecurityClassification, FIPSCryptoUtils, AuditEvent, AuditSeverity, AuditLogger
)

# Setup logging for the test
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class TestStateReconciliationEngine(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.classification_system = SecurityClassification(default_level="UNCLASSIFIED")
        self.crypto_utils = FIPSCryptoUtils()
        self.audit_logger = AuditLogger()
        self.engine = StateReconciliationEngine(
            classification_system=self.classification_system,
            crypto_utils=self.crypto_utils,
            audit_logger=self.audit_logger
        )
        self.maxDiff = None # To see full diffs on assertion failures

    async def test_no_conflict(self):
        local = {"a": 1, "b": "hello"}
        remote = {"a": 1, "b": "hello"}
        
        result = await self.engine.reconcile_contexts(local, remote)
        self.assertEqual(result.status, ReconciliationStatus.SUCCESS)
        self.assertEqual(result.merged_context, {"a": 1, "b": "hello", "_merge_checksum": result.merged_context["_merge_checksum"]})
        self.assertIn("_merge_checksum", result.merged_context)
        del result.merged_context["_merge_checksum"]

    async def test_remote_addition(self):
        local = {"a": 1}
        remote = {"a": 1, "b": "new_item"}
        
        result = await self.engine.reconcile_contexts(local, remote)
        self.assertEqual(result.status, ReconciliationStatus.SUCCESS)
        self.assertEqual(result.merged_context, {"a": 1, "b": "new_item", "_merge_checksum": result.merged_context["_merge_checksum"]})
        self.assertIn("_merge_checksum", result.merged_context)
        del result.merged_context["_merge_checksum"]
        self.assertEqual(len(result.conflicts_detected), 0)

    async def test_local_addition(self):
        local = {"a": 1, "b": "new_item"}
        remote = {"a": 1}
        
        result = await self.engine.reconcile_contexts(local, remote)
        self.assertEqual(result.status, ReconciliationStatus.SUCCESS)
        self.assertEqual(result.merged_context, {"a": 1, "b": "new_item", "_merge_checksum": result.merged_context["_merge_checksum"]})
        self.assertIn("_merge_checksum", result.merged_context)
        del result.merged_context["_merge_checksum"]
        self.assertEqual(len(result.conflicts_detected), 0)

    async def test_modify_modify_conflict_unclassified(self):
        local = {"a": 1, "b": "local_change"}
        remote = {"a": 1, "b": "remote_change"}
        base = {"a": 1, "b": "original"}

        result = await self.engine.reconcile_contexts(
            local, remote, common_ancestor=base,
            local_classification=ClassificationLevel.UNCLASSIFIED,
            remote_classification=ClassificationLevel.UNCLASSIFIED
        )
        self.assertEqual(result.status, ReconciliationStatus.CONFLICTS_RESOLVED)
        self.assertEqual(result.merged_context["b"], "local_change | remote_change") # Auto-resolved
        self.assertEqual(len(result.conflicts_detected), 1)
        self.assertEqual(result.conflicts_detected[0].conflict_type, ConflictType.CONTENT_CONFLICT)
        self.assertEqual(result.conflicts_detected[0].resolution_strategy, ResolutionStrategy.AUTOMATIC_MERGE)

    async def test_modify_modify_conflict_secret_manual_resolution(self):
        local = {"a": 1, "b": "local_secret_change"}
        remote = {"a": 1, "b": "remote_secret_change"}
        base = {"a": 1, "b": "original_secret"}

        # Set engine to SECRET clearance for this test
        self.engine.classification.default_level = ClassificationLevel.SECRET

        result = await self.engine.reconcile_contexts(
            local, remote, common_ancestor=base,
            local_classification=ClassificationLevel.SECRET,
            remote_classification=ClassificationLevel.SECRET
        )
        self.assertEqual(result.status, ReconciliationStatus.MANUAL_INTERVENTION_REQUIRED)
        # For SECRET, it should require manual intervention for content conflicts
        self.assertNotIn("b", result.merged_context) # Should not be auto-resolved and removed
        self.assertEqual(len(result.conflicts_detected), 1)
        self.assertEqual(result.conflicts_detected[0].conflict_type, ConflictType.CONTENT_CONFLICT)
        self.assertEqual(result.conflicts_detected[0].resolution_strategy, ResolutionStrategy.MANUAL_RESOLUTION)

    async def test_classification_conflict_higher_clearance_required(self):
        local = {"a": 1}
        remote = {"a": 1}

        # Engine is UNCLASSIFIED, but remote context is TOP_SECRET
        result = await self.engine.reconcile_contexts(
            local, remote,
            local_classification=ClassificationLevel.UNCLASSIFIED,
            remote_classification=ClassificationLevel.TOP_SECRET
        )
        self.assertEqual(result.status, ReconciliationStatus.SECURITY_VIOLATION)
        self.assertIn("Classification violation: insufficient clearance", result.audit_trail)

    async def test_classification_conflict_resolved_highest_wins(self):
        local = {"a": 1, "classification": "UNCLASSIFIED"}
        remote = {"a": 1, "classification": "SECRET"}

        # Engine is SECRET clearance
        self.engine.classification.default_level = ClassificationLevel.SECRET

        result = await self.engine.reconcile_contexts(
            local, remote,
            local_classification=ClassificationLevel.UNCLASSIFIED,
            remote_classification=ClassificationLevel.SECRET
        )
        self.assertEqual(result.status, ReconciliationStatus.CONFLICTS_RESOLVED)
        self.assertEqual(result.classification_level, ClassificationLevel.SECRET)
        self.assertEqual(len(result.conflicts_detected), 1)
        self.assertEqual(result.conflicts_detected[0].conflict_type, ConflictType.CLASSIFICATION_CONFLICT)
        self.assertEqual(result.conflicts_detected[0].resolution_strategy, ResolutionStrategy.HIGHEST_CLASSIFICATION)
        self.assertEqual(result.conflicts_detected[0].resolved_value, ClassificationLevel.SECRET.value)

    async def test_empty_contexts(self):
        local = {}
        remote = {}
        
        result = await self.engine.reconcile_contexts(local, remote)
        self.assertEqual(result.status, ReconciliationStatus.SUCCESS)
        self.assertIn("_merge_checksum", result.merged_context)
        del result.merged_context["_merge_checksum"]
        self.assertEqual(result.merged_context, {})
        self.assertEqual(len(result.conflicts_detected), 0)

    async def test_complex_scenario(self):
        local = {"a": 1, "b": "local_b", "c": "local_c", "d": "common", "classification": "UNCLASSIFIED"}
        remote = {"a": 2, "b": "remote_b", "e": "remote_e", "d": "common", "classification": "UNCLASSIFIED"}
        base = {"a": 0, "b": "original_b", "d": "common", "classification": "UNCLASSIFIED"}

        result = await self.engine.reconcile_contexts(local, remote, common_ancestor=base)
        self.assertEqual(result.status, ReconciliationStatus.CONFLICTS_RESOLVED)
        self.assertEqual(result.merged_context["a"], 1.5) # Auto-resolved (average)
        self.assertEqual(result.merged_context["b"], "local_b | remote_b") # Auto-resolved
        self.assertEqual(result.merged_context["c"], "local_c") # local addition
        self.assertEqual(result.merged_context["d"], "common") # no conflict
        self.assertEqual(result.merged_context["e"], "remote_e") # remote addition
        self.assertEqual(len(result.conflicts_detected), 2) # a, b

    async def test_performance_metrics_update(self):
        local = {"data": "a" * 1000}
        remote = {"data": "b" * 1000}
        base = {"data": "c" * 1000}

        await self.engine.reconcile_contexts(local, remote, common_ancestor=base)
        metrics = self.engine.validate()["actual_performance"]
        self.assertGreater(metrics["total_reconciliation_ms"], 0)
        self.assertGreater(metrics["conflict_detection_ms"], 0)

    async def test_data_integrity_checksum(self):
        local = {"a": 1, "b": "test"}
        remote = {"a": 1, "b": "test"}

        result = await self.engine.reconcile_contexts(local, remote)
        self.assertTrue(result.security_validations["data_integrity"])
        self.assertIn("_merge_checksum", result.merged_context)

if __name__ == '__main__':
    unittest.main()