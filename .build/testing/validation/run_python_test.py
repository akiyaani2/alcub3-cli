import sys
from pathlib import Path
import unittest

# Add the project root to sys.path
project_root = Path(__file__).resolve().parent
sys.path.insert(0, str(project_root))

# Import the test module
from security_framework.tests.reconciliation_engine_test import TestStateReconciliationEngine

if __name__ == '__main__':
    unittest.main()
