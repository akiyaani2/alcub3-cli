import unittest
import asyncio
import logging
from datetime import datetime

from ros2_adapter import ROS2Adapter

# Setup logging for the test
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class TestROS2Adapter(unittest.TestCase):

    def setUp(self):
        # Mock security_profile for initialization
        self.mock_security_profile = {
            "robot_id": "ros2_test_01",
            "classification_level": "UNCLASSIFIED",
            "validation_level": "BASIC"
        }
        self.adapter = ROS2Adapter("ros2_test_01", self.mock_security_profile)

    def test_initialization(self):
        self.assertIsNotNone(self.adapter)
        self.assertEqual(self.adapter.robot_id, "ros2_test_01")
        self.assertEqual(self.adapter.security_profile, self.mock_security_profile)

    async def test_initialize_ros2_connection(self):
        ros2_config = {"ip": "127.0.0.1", "port": 11311}
        success = await self.adapter.initialize_ros2_connection(ros2_config)
        self.assertTrue(success)

    async def test_validate_command(self):
        command = {"command_id": "cmd_001", "type": "move", "params": {"x": 1.0}}
        valid = await self.adapter.validate_command(command)
        self.assertTrue(valid)

    async def test_execute_emergency_stop(self):
        reason = "test_reason"
        success = await self.adapter.execute_emergency_stop(reason)
        self.assertTrue(success)

    async def test_get_security_status(self):
        status = await self.adapter.get_security_status()
        self.assertIn("status", status)
        self.assertEqual(status["status"], "mock_operational")

    async def test_update_security_profile(self):
        new_profile = {"robot_id": "ros2_test_01", "classification_level": "SECRET"}
        success = await self.adapter.update_security_profile(new_profile)
        self.assertTrue(success)

# Helper to run async tests
def run_async_test(coro):
    def wrapper(*args, **kwargs):
        return asyncio.run(coro(*args, **kwargs))
    return wrapper

# Apply wrapper to async test methods
for name in dir(TestROS2Adapter):
    if name.startswith('test_async_') or name.startswith('test_initialize_') or name.startswith('test_validate_') or name.startswith('test_execute_') or name.startswith('test_get_') or name.startswith('test_update_'):
        attr = getattr(TestROS2Adapter, name)
        if asyncio.iscoroutinefunction(attr):
            setattr(TestROS2Adapter, name, run_async_test(attr))

if __name__ == '__main__':
    unittest.main()
