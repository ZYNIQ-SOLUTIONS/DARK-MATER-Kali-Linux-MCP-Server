#!/usr/bin/env python3
"""
MCP Kali Server - First Launch Setup and Test Runner
Ensures project integrity by running comprehensive tests on first launch.
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime

class FirstLaunchSetup:
    """Handles first launch setup and testing"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.setup_marker = self.project_root / ".setup_completed"
        self.test_results_file = self.project_root / "test_results.json"
        
    def is_first_launch(self) -> bool:
        """Check if this is the first launch"""
        return not self.setup_marker.exists()
    
    def mark_setup_complete(self):
        """Mark setup as completed"""
        try:
            with open(self.setup_marker, 'w') as f:
                json.dump({
                    "setup_completed": datetime.now().isoformat(),
                    "version": "2.0.0"
                }, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not create setup marker: {e}")
    
    def run_comprehensive_tests(self) -> bool:
        """Run the comprehensive test suite"""
        print("\n🔍 FIRST LAUNCH DETECTED")
        print("="*60)
        print("Running comprehensive tests to ensure project integrity...")
        print("This is a one-time setup process.")
        print("="*60)
        
        # Run the test suite
        test_runner = self.project_root / "tests" / "run_tests.py"
        
        if not test_runner.exists():
            print("❌ Test runner not found. Skipping tests.")
            return True
        
        try:
            env = os.environ.copy()
            env["PYTHONPATH"] = str(self.project_root)
            env["MCP_IN_DOCKER"] = "true"
            result = subprocess.run([
                sys.executable, str(test_runner)
            ], cwd=self.project_root, env=env)
            
            return result.returncode == 0
            
        except Exception as e:
            print(f"❌ Error running tests: {e}")
            return False
    
    def show_test_results(self):
        """Show previous test results if available"""
        if self.test_results_file.exists():
            try:
                with open(self.test_results_file, 'r') as f:
                    results = json.load(f)
                
                print(f"\n📊 LAST TEST RESULTS")
                print("-"*40)
                print(f"Date: {results.get('timestamp', 'Unknown')}")
                print(f"Total Tests: {results.get('total_tests', 0)}")
                print(f"Passed: {results.get('passed', 0)}")
                print(f"Failed: {results.get('failed', 0)}")
                print(f"Status: {results.get('summary', 'Unknown')}")
                
            except Exception as e:
                print(f"⚠️  Could not read test results: {e}")
    
    def setup(self) -> bool:
        """Run first launch setup"""
        if self.is_first_launch():
            print("🚀 MCP KALI SERVER - FIRST LAUNCH SETUP")
            print("="*60)
            
            # Run tests
            test_success = self.run_comprehensive_tests()
            
            if test_success:
                print("\n✅ Setup completed successfully!")
                self.mark_setup_complete()
                return True
            else:
                print("\n❌ Setup failed due to test failures.")
                print("Please review the test results and fix any issues.")
                return False
        else:
            # Not first launch, just show previous results
            self.show_test_results()
            return True

def ensure_project_integrity():
    """Ensure project integrity before starting server"""
    setup = FirstLaunchSetup()
    return setup.setup()

if __name__ == "__main__":
    # Can be run standalone
    setup = FirstLaunchSetup()
    success = setup.setup()
    sys.exit(0 if success else 1)