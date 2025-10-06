#!/usr/bin/env python3
"""
Comprehensive Testing Harness for CPE464 Packet Trace Program
Tests all requirements specified in the assignment PDF
"""

import os
import sys
import subprocess
import difflib
import glob
import time
from pathlib import Path
from typing import List, Tuple, Dict, Optional
import argparse


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'


class TestResult:
    """Container for test results"""
    def __init__(self, name: str, passed: bool, message: str, details: str = ""):
        self.name = name
        self.passed = passed
        self.message = message
        self.details = details


class TraceTestHarness:
    """Main test harness class"""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.results: List[TestResult] = []
        self.current_dir = os.getcwd()

    def log(self, message: str, color: str = ""):
        """Log a message with optional color"""
        if color:
            print(f"{color}{message}{Colors.END}")
        else:
            print(message)

    def log_verbose(self, message: str):
        """Log only if verbose mode is enabled"""
        if self.verbose:
            print(f"  {message}")

    def run_command(self, command: List[str], timeout: int = 30) -> Tuple[int, str, str]:
        """Run a command and return (returncode, stdout, stderr)"""
        try:
            self.log_verbose(f"Running: {' '.join(command)}")
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=self.current_dir
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", f"Command timed out after {timeout} seconds"
        except FileNotFoundError:
            return -1, "", f"Command not found: {command[0]}"

    def test_makefile_exists(self) -> TestResult:
        """Test 1: Verify Makefile exists"""
        if os.path.exists("Makefile"):
            return TestResult("Makefile exists", True, "Makefile found")
        return TestResult("Makefile exists", False, "Makefile not found")

    def test_required_files_exist(self) -> TestResult:
        """Test 2: Verify required source files exist"""
        required_files = ["trace.c", "trace.h", "checksum.c", "checksum.h"]
        missing_files = []

        for file in required_files:
            if not os.path.exists(file):
                missing_files.append(file)

        if not missing_files:
            return TestResult("Required files exist", True, "All required files found")
        else:
            return TestResult("Required files exist", False,
                            f"Missing files: {', '.join(missing_files)}")

    def test_clean_build(self) -> TestResult:
        """Test 3: Test clean build process"""
        # First, try to clean
        self.log_verbose("Running make clean...")
        returncode, stdout, stderr = self.run_command(["make", "clean"])

        # Then try to build
        self.log_verbose("Running make...")
        returncode, stdout, stderr = self.run_command(["make"])

        if returncode == 0:
            # Check if executable was created
            if os.path.exists("trace"):
                return TestResult("Clean build", True, "Build successful")
            else:
                return TestResult("Clean build", False, "Build succeeded but no executable created")
        else:
            return TestResult("Clean build", False, f"Build failed: {stderr}")

    def test_no_warnings(self) -> TestResult:
        """Test 4: Verify build produces no warnings"""
        returncode, stdout, stderr = self.run_command(["make", "clean"])
        returncode, stdout, stderr = self.run_command(["make"])

        # Check for warnings in stderr
        warning_keywords = ["warning:", "Warning:", "WARNING:"]
        warnings_found = any(keyword in stderr for keyword in warning_keywords)

        if not warnings_found:
            return TestResult("No build warnings", True, "Build completed without warnings")
        else:
            return TestResult("No build warnings", False, f"Warnings found: {stderr}")

    def test_required_functions_exist(self) -> TestResult:
        """Test 5: Verify required functions exist in source code"""
        required_functions = ["ethernet(", "arp(", "ip(", "tcp(", "icmp("]
        missing_functions = []

        try:
            with open("trace.c", "r") as f:
                content = f.read()

            for func in required_functions:
                if func not in content:
                    missing_functions.append(func.rstrip("("))
        except FileNotFoundError:
            return TestResult("Required functions exist", False, "trace.c not found")

        if not missing_functions:
            return TestResult("Required functions exist", True, "All required functions found")
        else:
            return TestResult("Required functions exist", False,
                            f"Missing functions: {', '.join(missing_functions)}")

    def test_no_bit_shifting(self) -> TestResult:
        """Test 6: Verify no bit shifting operators are used"""
        prohibited_operators = ["<<", ">>"]
        files_to_check = ["trace.c", "trace.h"]
        violations = []

        for file in files_to_check:
            if os.path.exists(file):
                try:
                    with open(file, "r") as f:
                        lines = f.readlines()

                    for line_num, line in enumerate(lines, 1):
                        # Skip comments
                        if "//" in line:
                            line = line.split("//")[0]
                        if "/*" in line:
                            continue  # Simplified comment detection

                        for op in prohibited_operators:
                            if op in line:
                                violations.append(f"{file}:{line_num}: {line.strip()}")
                except FileNotFoundError:
                    continue

        if not violations:
            return TestResult("No bit shifting", True, "No prohibited bit shifting operators found")
        else:
            details = "\n".join(violations)
            return TestResult("No bit shifting", False,
                            f"Bit shifting operators found", details)

    def find_test_files(self) -> List[Tuple[str, str]]:
        """Find all .pcap and corresponding .out files"""
        pcap_files = glob.glob("test_files/*.pcap")
        test_pairs = []

        for pcap_file in pcap_files:
            out_file = pcap_file.replace(".pcap", ".out")
            if os.path.exists(out_file):
                test_pairs.append((pcap_file, out_file))

        return test_pairs

    def test_trace_execution(self, pcap_file: str, expected_output_file: str) -> TestResult:
        """Test execution of trace program against expected output"""
        if not os.path.exists("trace"):
            return TestResult(f"Execute {pcap_file}", False, "trace executable not found")

        # Run the trace program
        returncode, stdout, stderr = self.run_command(["./trace", pcap_file])

        if returncode != 0:
            return TestResult(f"Execute {pcap_file}", False,
                            f"Execution failed: {stderr}")

        # Compare with expected output
        try:
            with open(expected_output_file, "r") as f:
                expected = f.read()
        except FileNotFoundError:
            return TestResult(f"Execute {pcap_file}", False,
                            f"Expected output file not found: {expected_output_file}")

        # Normalize whitespace for comparison (as per assignment requirements)
        actual_lines = [line.rstrip() for line in stdout.split('\n')]
        expected_lines = [line.rstrip() for line in expected.split('\n')]

        # Remove empty lines at end
        while actual_lines and actual_lines[-1] == '':
            actual_lines.pop()
        while expected_lines and expected_lines[-1] == '':
            expected_lines.pop()

        if actual_lines == expected_lines:
            return TestResult(f"Execute {pcap_file}", True, "Output matches expected")
        else:
            # Generate diff for debugging
            diff = list(difflib.unified_diff(
                expected_lines, actual_lines,
                fromfile=expected_output_file,
                tofile="actual_output",
                lineterm=""
            ))
            diff_text = "\n".join(diff[:50])  # Limit diff output
            if len(diff) > 50:
                diff_text += f"\n... ({len(diff) - 50} more lines)"

            return TestResult(f"Execute {pcap_file}", False,
                            "Output does not match expected", diff_text)

    def test_protocol_coverage(self) -> TestResult:
        """Test 7: Verify protocol coverage across test files"""
        test_files = self.find_test_files()
        if not test_files:
            return TestResult("Protocol coverage", False, "No test files found")

        # Analyze what protocols are covered by the test files
        protocol_coverage = {
            "Ethernet": False,
            "ARP": False,
            "IP": False,
            "ICMP": False,
            "TCP": False,
            "UDP": False
        }

        test_file_info = []
        for pcap_file, out_file in test_files:
            try:
                with open(out_file, "r") as f:
                    content = f.read()

                protocols_in_file = []
                if "Ethernet Header" in content:
                    protocol_coverage["Ethernet"] = True
                    protocols_in_file.append("Ethernet")
                if "ARP header" in content:
                    protocol_coverage["ARP"] = True
                    protocols_in_file.append("ARP")
                if "IP Header" in content:
                    protocol_coverage["IP"] = True
                    protocols_in_file.append("IP")
                if "ICMP Header" in content:
                    protocol_coverage["ICMP"] = True
                    protocols_in_file.append("ICMP")
                if "TCP Header" in content:
                    protocol_coverage["TCP"] = True
                    protocols_in_file.append("TCP")
                if "UDP Header" in content:
                    protocol_coverage["UDP"] = True
                    protocols_in_file.append("UDP")

                test_file_info.append(f"{pcap_file}: {', '.join(protocols_in_file)}")
            except FileNotFoundError:
                continue

        covered_protocols = [k for k, v in protocol_coverage.items() if v]
        missing_protocols = [k for k, v in protocol_coverage.items() if not v]

        details = "\n".join(test_file_info)

        if len(covered_protocols) >= 4:  # At least Ethernet, ARP, IP, and one transport protocol
            return TestResult("Protocol coverage", True,
                            f"Good coverage: {', '.join(covered_protocols)}", details)
        else:
            return TestResult("Protocol coverage", False,
                            f"Limited coverage. Missing: {', '.join(missing_protocols)}", details)

    def test_checksum_usage(self) -> TestResult:
        """Test 8: Verify checksum.c functions are being used"""
        try:
            with open("trace.c", "r") as f:
                content = f.read()
        except FileNotFoundError:
            return TestResult("Checksum usage", False, "trace.c not found")

        # Look for checksum function calls
        checksum_indicators = ["checksum(", "in_cksum(", "#include \"checksum.h\""]
        found_usage = any(indicator in content for indicator in checksum_indicators)

        if found_usage:
            return TestResult("Checksum usage", True, "Checksum functions are being used")
        else:
            return TestResult("Checksum usage", False,
                            "No evidence of checksum function usage found")

    def test_packed_structs(self) -> TestResult:
        """Test 9: Verify struct headers have __attribute__((packed)) by checking source"""
        try:
            with open("trace.h", "r") as f:
                content = f.read()
        except FileNotFoundError:
            return TestResult("Packed structs", False, "trace.h not found")

        # Check for struct definitions that should be packed
        protocol_structs = [
            "ethernet_header",
            "arp_header",
            "ip_header",
            "icmp_header",
            "tcp_header",
            "udp_header"
        ]

        unpacked_structs = []
        for struct_name in protocol_structs:
            # Look for struct definition
            if f"typedef struct {struct_name}" in content:
                # Find the end of this struct definition
                start_pos = content.find(f"typedef struct {struct_name}")
                if start_pos != -1:
                    # Find the closing brace and typedef name
                    remaining_content = content[start_pos:]
                    closing_pattern = f"}} {struct_name}_t;"
                    closing_pos = remaining_content.find(closing_pattern)

                    if closing_pos != -1:
                        struct_definition = remaining_content[:closing_pos + len(closing_pattern)]
                        # Check if __attribute__((packed)) is present
                        if "__attribute__((packed))" not in struct_definition:
                            unpacked_structs.append(struct_name)

        if not unpacked_structs:
            return TestResult("Packed structs", True, f"All protocol structs have __attribute__((packed))")
        else:
            return TestResult("Packed structs", False,
                            f"Missing __attribute__((packed)): {', '.join(unpacked_structs)}")

    def run_all_tests(self):
        """Run all tests and generate report"""
        self.log(f"{Colors.BOLD}CPE464 Packet Trace Testing Harness{Colors.END}")
        self.log("=" * 50)

        # Basic file and build tests
        basic_tests = [
            self.test_makefile_exists(),
            self.test_required_files_exist(),
            self.test_clean_build(),
            self.test_no_warnings(),
            self.test_required_functions_exist(),
            self.test_no_bit_shifting(),
            self.test_checksum_usage(),
            self.test_packed_structs(),
            self.test_protocol_coverage()
        ]

        self.results.extend(basic_tests)

        # Execution tests for each test file
        test_files = self.find_test_files()
        self.log(f"\nFound {len(test_files)} test file pairs:")
        for pcap, out in test_files:
            self.log(f"  {pcap} -> {out}")

        for pcap_file, out_file in test_files:
            result = self.test_trace_execution(pcap_file, out_file)
            self.results.append(result)

        # Generate summary report
        self.generate_report()

    def generate_report(self):
        """Generate and display test report"""
        self.log(f"\n{Colors.BOLD}Test Results Summary{Colors.END}")
        self.log("=" * 50)

        passed_tests = [r for r in self.results if r.passed]
        failed_tests = [r for r in self.results if not r.passed]

        # Display results
        for result in self.results:
            status_color = Colors.GREEN if result.passed else Colors.RED
            status_text = "PASS" if result.passed else "FAIL"

            self.log(f"[{status_color}{status_text}{Colors.END}] {result.name}: {result.message}")

            if not result.passed and result.details and self.verbose:
                self.log(f"  Details:\n{result.details}")

        # Summary statistics
        total_tests = len(self.results)
        pass_rate = (len(passed_tests) / total_tests * 100) if total_tests > 0 else 0

        self.log(f"\n{Colors.BOLD}Summary:{Colors.END}")
        self.log(f"Total tests: {total_tests}")
        self.log(f"Passed: {Colors.GREEN}{len(passed_tests)}{Colors.END}")
        self.log(f"Failed: {Colors.RED}{len(failed_tests)}{Colors.END}")
        self.log(f"Pass rate: {pass_rate:.1f}%")

        # Grade estimate based on PDF requirements
        self.estimate_grade()

    def estimate_grade(self):
        """Estimate grade based on PDF grading criteria and test results"""
        self.log(f"\n{Colors.BOLD}Grade Estimation (based on test results):{Colors.END}")

        # Get list of passed execution tests
        execution_tests = [r for r in self.results if "Execute" in r.name]
        passed_execution_tests = [r for r in execution_tests if r.passed]

        if execution_tests:
            success_rate = len(passed_execution_tests) / len(execution_tests)
            self.log(f"Execution test success rate: {success_rate:.1%} ({len(passed_execution_tests)}/{len(execution_tests)})")

        # Check for specific capabilities based on test file types
        ethernet_working = any("ArpTest" in r.name and r.passed for r in self.results)
        arp_working = ethernet_working  # ARP test includes ethernet

        # Check for IP/ICMP capability
        ip_working = any(any(test_type in r.name for test_type in ["PingTest", "IP_bad_checksum"]) and r.passed for r in self.results)

        # Check for TCP capability
        tcp_working = any(any(test_type in r.name for test_type in ["smallTCP", "TCP_bad_checksum", "Http", "largeMix"]) and r.passed for r in self.results)

        # Check for UDP capability
        udp_working = any(any(test_type in r.name for test_type in ["UDPfile", "largeMix"]) and r.passed for r in self.results)

        # Calculate scores based on PDF grading criteria
        ethernet_score = 10 if ethernet_working else 0
        arp_score = 10 if arp_working else 0
        ip_score = 30 if ip_working else 0
        tcp_udp_score = 50 if (tcp_working and udp_working) else 25 if (tcp_working or udp_working) else 0

        estimated_grade = ethernet_score + arp_score + ip_score + tcp_udp_score

        self.log(f"Ethernet headers (10%): {ethernet_score}/10 - {'✓' if ethernet_working else '✗'}")
        self.log(f"ARP headers (10%): {arp_score}/10 - {'✓' if arp_working else '✗'}")
        self.log(f"IP/ICMP headers (30%): {ip_score}/30 - {'✓' if ip_working else '✗'}")
        self.log(f"TCP/UDP headers (50%): {tcp_udp_score}/50 - {'✓ TCP' if tcp_working else '✗ TCP'} {'✓ UDP' if udp_working else '✗ UDP'}")
        self.log(f"{Colors.BOLD}Estimated grade: {estimated_grade}/100{Colors.END}")


def main():
    parser = argparse.ArgumentParser(description="CPE464 Packet Trace Testing Harness")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Enable verbose output")
    parser.add_argument("--quick", action="store_true",
                       help="Run only basic tests (skip execution tests)")

    args = parser.parse_args()

    harness = TraceTestHarness(verbose=args.verbose)

    if args.quick:
        harness.log("Running quick tests only...")
        # Run only basic tests
        basic_tests = [
            harness.test_makefile_exists(),
            harness.test_required_files_exist(),
            harness.test_clean_build(),
            harness.test_no_warnings(),
            harness.test_required_functions_exist(),
            harness.test_no_bit_shifting(),
            harness.test_checksum_usage(),
            harness.test_packed_structs(),
        ]
        harness.results.extend(basic_tests)
        harness.generate_report()
    else:
        harness.run_all_tests()


if __name__ == "__main__":
    main()