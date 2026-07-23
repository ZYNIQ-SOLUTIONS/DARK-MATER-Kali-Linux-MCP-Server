#!/usr/bin/env python3
"""
MCP Kali Server - Comprehensive Test Runner
Runs all tests to ensure project integrity on first launch
"""

import os
import sys
import time
import subprocess
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Tuple

class TestRunner:
    """Comprehensive test runner for MCP Kali Server"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.tests_dir = self.project_root / "tests"
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "test_results": [],
            "summary": ""
        }
        
    def print_header(self):
        """Print test runner header"""
        print("\n" + "="*80)
        print("🧪 MCP KALI SERVER - COMPREHENSIVE TEST SUITE")
        print("="*80)
        print(f"📅 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"📁 Project Root: {self.project_root}")
        print(f"🔬 Tests Directory: {self.tests_dir}")
        print("="*80)

    def check_environment(self) -> bool:
        """Check if the test environment is properly set up"""
        print("\n🔍 ENVIRONMENT CHECK")
        print("-" * 40)
        
        checks = []
        
        # Check Python version
        python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        print(f"🐍 Python Version: {python_version}")
        checks.append(("Python >= 3.8", sys.version_info >= (3, 8)))
        
        # Check if we're in a virtual environment or running inside Docker/Kubernetes container
        in_venv = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
        is_docker = os.path.exists('/.dockerenv') or os.path.exists('/run/.containerenv') or os.environ.get("MCP_IN_DOCKER") == "true"
        
        print(f"🏠 Virtual Environment: {'Yes' if in_venv else 'No'} (Bypassed)")
        print(f"🐳 Container Environment (Docker): {'Yes' if is_docker else 'No'}")
        
        checks.append(("Virtual Environment or Containerized", True))
        
        # Check required modules
        required_modules = [
            "fastapi", "uvicorn", "pydantic", "requests", 
            "websockets", "jsonschema", "cryptography"
        ]
        
        for module in required_modules:
            try:
                __import__(module)
                print(f"📦 {module}: ✅ Available")
                checks.append((f"Module {module}", True))
            except ImportError:
                print(f"📦 {module}: ❌ Missing")
                checks.append((f"Module {module}", False))
        
        # Check project structure
        required_dirs = ["mcp_server", "mcp_tools", "tests"]
        for dir_name in required_dirs:
            dir_path = self.project_root / dir_name
            exists = dir_path.exists()
            print(f"📁 {dir_name}/: {'✅' if exists else '❌'}")
            checks.append((f"Directory {dir_name}", exists))
        
        # Summary
        passed_checks = sum(1 for _, status in checks if status)
        total_checks = len(checks)
        
        print(f"\n📊 Environment Checks: {passed_checks}/{total_checks} passed")
        
        if passed_checks == total_checks:
            print("✅ Environment is ready for testing!")
            return True
        else:
            print("❌ Environment setup issues detected!")
            for name, status in checks:
                if not status:
                    print(f"   ⚠️  {name}: Failed")
            return False

    def discover_tests(self) -> Dict[str, List[Path]]:
        """Discover all test files organized by category"""
        test_categories = {
            "unit": [],
            "integration": [], 
            "acceptance": [],
            "system": []
        }
        
        print("\n🔍 TEST DISCOVERY")
        print("-" * 40)
        
        for category in test_categories.keys():
            category_dir = self.tests_dir / category
            if category_dir.exists():
                test_files = list(category_dir.glob("test_*.py"))
                test_categories[category] = test_files
                print(f"📂 {category.title()} Tests: {len(test_files)} found")
                for test_file in test_files:
                    print(f"   • {test_file.name}")
            else:
                print(f"📂 {category.title()} Tests: Directory not found")
        
        # Check for standalone test files
        standalone_tests = list(self.tests_dir.glob("test_*.py"))
        if standalone_tests:
            test_categories["system"] = standalone_tests
            print(f"📂 System Tests: {len(standalone_tests)} found")
            for test_file in standalone_tests:
                print(f"   • {test_file.name}")
        
        total_tests = sum(len(tests) for tests in test_categories.values())
        print(f"\n📊 Total Tests Discovered: {total_tests}")
        
        return test_categories

    def run_test_file(self, test_file: Path, category: str) -> Tuple[bool, str]:
        """Run a single test file and return success status and output"""
        print(f"\n🧪 Running {category} test: {test_file.name}")
        
        try:
            # Change to project root for consistent imports
            original_cwd = os.getcwd()
            os.chdir(self.project_root)
            
            # Run the test
            env = os.environ.copy()
            env["PYTHONPATH"] = str(self.project_root)
            env["PYTHONUTF8"] = "1"
            
            result = subprocess.run([
                sys.executable, str(test_file)
            ], capture_output=True, text=True, timeout=60, env=env)
            
            os.chdir(original_cwd)
            
            success = result.returncode == 0
            output = result.stdout + result.stderr
            
            if success:
                print(f"   ✅ PASSED")
            else:
                print(f"   ❌ FAILED (exit code: {result.returncode})")
                if output:
                    print(f"   📝 Output: {output[:200]}...")
            
            return success, output
            
        except subprocess.TimeoutExpired:
            print(f"   ⏰ TIMEOUT (60s exceeded)")
            return False, "Test timed out after 60 seconds"
        except Exception as e:
            print(f"   ❌ ERROR: {e}")
            return False, str(e)

    def run_all_tests(self) -> bool:
        """Run all discovered tests"""
        test_categories = self.discover_tests()
        
        print("\n🚀 RUNNING ALL TESTS")
        print("="*80)
        
        start_time = time.time()
        
        # Run tests by category
        for category, test_files in test_categories.items():
            if not test_files:
                continue
                
            print(f"\n📂 {category.upper()} TESTS")
            print("-" * 40)
            
            for test_file in test_files:
                success, output = self.run_test_file(test_file, category)
                
                self.results["total_tests"] += 1
                if success:
                    self.results["passed"] += 1
                else:
                    self.results["failed"] += 1
                
                self.results["test_results"].append({
                    "category": category,
                    "file": test_file.name,
                    "success": success,
                    "output": output[:500] if output else ""
                })
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Generate summary
        self.generate_summary(duration)
        
        return self.results["failed"] == 0

    def generate_summary(self, duration: float):
        """Generate and display test summary"""
        passed = self.results["passed"]
        failed = self.results["failed"]
        total = self.results["total_tests"]
        
        print("\n" + "="*80)
        print("📊 TEST SUMMARY")
        print("="*80)
        print(f"⏱️  Duration: {duration:.2f} seconds")
        print(f"📈 Total Tests: {total}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"📊 Success Rate: {(passed/total*100):.1f}%" if total > 0 else "📊 Success Rate: 0%")
        
        if failed > 0:
            print(f"\n❌ FAILED TESTS:")
            for result in self.results["test_results"]:
                if not result["success"]:
                    print(f"   • {result['category']}/{result['file']}")
        
        if passed == total and total > 0:
            print("\n🎉 ALL TESTS PASSED! Project is ready for use.")
            self.results["summary"] = "All tests passed - project ready"
        elif failed > 0:
            print(f"\n⚠️  {failed} tests failed. Please review and fix issues before deployment.")
            self.results["summary"] = f"{failed} tests failed - review required"
        else:
            print("\n⚠️  No tests were found or executed.")
            self.results["summary"] = "No tests executed"
        
        print("="*80)

    def save_results(self):
        """Save test results to file"""
        results_file = self.project_root / "test_results.json"
        try:
            with open(results_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"💾 Test results saved to: {results_file}")
        except Exception as e:
            print(f"⚠️  Failed to save test results: {e}")

    def run(self) -> bool:
        """Main test runner method"""
        self.print_header()
        
        # Check environment
        if not self.check_environment():
            print("\n❌ Environment check failed. Please fix issues before running tests.")
            return False
        
        # Run all tests
        success = self.run_all_tests()
        
        # Save results
        self.save_results()
        
        return success

def main():
    """Main entry point"""
    runner = TestRunner()
    
    try:
        success = runner.run()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Test run interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Test runner error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()