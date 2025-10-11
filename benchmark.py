#!/usr/bin/env python3
"""
Performance benchmarking for CloudGuard Enhanced
"""

import time
import argparse
import sys
from typing import Dict, List, Any
import json
from datetime import datetime, timezone

# Mock AWS responses for benchmarking
MOCK_S3_BUCKETS = [
    {"Name": f"test-bucket-{i}"} for i in range(100)
]

MOCK_IAM_USERS = [
    {"UserName": f"user-{i}"} for i in range(50)
]

MOCK_SECURITY_GROUPS = [
    {
        "GroupId": f"sg-{i:08d}",
        "GroupName": f"test-sg-{i}",
        "IpPermissions": [
            {
                "FromPort": 22,
                "ToPort": 22,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    } for i in range(200)
]

MOCK_RDS_INSTANCES = [
    {
        "DBInstanceIdentifier": f"test-db-{i}",
        "PubliclyAccessible": True,
        "StorageEncrypted": False,
        "MultiAZ": False
    } for i in range(20)
]

MOCK_LAMBDA_FUNCTIONS = [
    {
        "FunctionName": f"test-function-{i}",
        "Runtime": "python3.6" if i % 2 == 0 else "python3.11"
    } for i in range(100)
]


class MockAWSScanner:
    """Mock scanner for performance testing"""
    
    def __init__(self, workers: int = 8):
        self.workers = workers
        self.findings = []
    
    def mock_scan_s3_buckets(self) -> List[Dict[str, Any]]:
        """Mock S3 bucket scanning"""
        findings = []
        for bucket in MOCK_S3_BUCKETS:
            # Simulate finding public access
            findings.append({
                "id": f"s3-public-{bucket['Name']}",
                "title": "S3 Bucket Public Access",
                "severity": "CRITICAL",
                "resource_id": bucket["Name"]
            })
        return findings
    
    def mock_scan_iam(self) -> List[Dict[str, Any]]:
        """Mock IAM scanning"""
        findings = []
        for user in MOCK_IAM_USERS:
            # Simulate finding unused keys
            findings.append({
                "id": f"iam-unused-key-{user['UserName']}",
                "title": "Unused IAM Access Key",
                "severity": "LOW",
                "resource_id": user["UserName"]
            })
        return findings
    
    def mock_scan_ec2_sgs(self) -> List[Dict[str, Any]]:
        """Mock EC2 security group scanning"""
        findings = []
        for sg in MOCK_SECURITY_GROUPS:
            # Simulate finding public access
            findings.append({
                "id": f"ec2-sg-open-{sg['GroupId']}",
                "title": "Security Group Public Access",
                "severity": "CRITICAL",
                "resource_id": sg["GroupId"]
            })
        return findings
    
    def mock_scan_rds(self) -> List[Dict[str, Any]]:
        """Mock RDS scanning"""
        findings = []
        for db in MOCK_RDS_INSTANCES:
            # Simulate finding public access
            findings.append({
                "id": f"rds-public-{db['DBInstanceIdentifier']}",
                "title": "RDS Public Access",
                "severity": "CRITICAL",
                "resource_id": db["DBInstanceIdentifier"]
            })
        return findings
    
    def mock_scan_lambda(self) -> List[Dict[str, Any]]:
        """Mock Lambda scanning"""
        findings = []
        for func in MOCK_LAMBDA_FUNCTIONS:
            if func["Runtime"] == "python3.6":
                findings.append({
                    "id": f"lambda-runtime-{func['FunctionName']}",
                    "title": "Deprecated Lambda Runtime",
                    "severity": "HIGH",
                    "resource_id": func["FunctionName"]
                })
        return findings
    
    def run_benchmark(self, account_size: str = "medium") -> Dict[str, Any]:
        """Run performance benchmark"""
        print(f"🚀 Starting CloudGuard performance benchmark...")
        print(f"📊 Account size: {account_size}")
        print(f"⚡ Workers: {self.workers}")
        print("-" * 60)
        
        start_time = time.time()
        
        # Run mock scans
        scan_methods = [
            ("S3 Buckets", self.mock_scan_s3_buckets),
            ("IAM Users", self.mock_scan_iam),
            ("EC2 Security Groups", self.mock_scan_ec2_sgs),
            ("RDS Instances", self.mock_scan_rds),
            ("Lambda Functions", self.mock_scan_lambda)
        ]
        
        all_findings = []
        scan_times = {}
        
        for scan_name, scan_method in scan_methods:
            scan_start = time.time()
            findings = scan_method()
            scan_duration = time.time() - scan_start
            
            all_findings.extend(findings)
            scan_times[scan_name] = scan_duration
            
            print(f"✅ {scan_name}: {len(findings)} findings in {scan_duration:.2f}s")
        
        total_duration = time.time() - start_time
        
        # Calculate statistics
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in all_findings:
            severity_counts[finding["severity"]] += 1
        
        # Calculate security score
        deductions = (
            severity_counts["CRITICAL"] * 15 +
            severity_counts["HIGH"] * 10 +
            severity_counts["MEDIUM"] * 5 +
            severity_counts["LOW"] * 2
        )
        security_score = max(0, 100 - deductions)
        
        # Determine grade
        if security_score >= 90:
            grade = "A"
        elif security_score >= 80:
            grade = "B"
        elif security_score >= 70:
            grade = "C"
        elif security_score >= 60:
            grade = "D"
        else:
            grade = "F"
        
        results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "account_size": account_size,
            "workers": self.workers,
            "total_duration": round(total_duration, 2),
            "total_findings": len(all_findings),
            "security_score": security_score,
            "grade": grade,
            "severity_breakdown": severity_counts,
            "scan_times": scan_times,
            "performance_metrics": {
                "findings_per_second": round(len(all_findings) / total_duration, 2),
                "average_scan_time": round(sum(scan_times.values()) / len(scan_times), 2),
                "parallel_efficiency": round((sum(scan_times.values()) / total_duration), 2)
            }
        }
        
        return results
    
    def print_results(self, results: Dict[str, Any]):
        """Print benchmark results"""
        print("\n" + "=" * 60)
        print("📊 BENCHMARK RESULTS")
        print("=" * 60)
        print(f"🎯 Security Score: {results['security_score']}/100 (Grade: {results['grade']})")
        print(f"🔍 Total Findings: {results['total_findings']}")
        print(f"⏱️  Total Duration: {results['total_duration']}s")
        print(f"⚡ Workers: {results['workers']}")
        print(f"📈 Findings/sec: {results['performance_metrics']['findings_per_second']}")
        print(f"🔄 Parallel Efficiency: {results['performance_metrics']['parallel_efficiency']}x")
        
        print(f"\n📊 Severity Breakdown:")
        for severity, count in results['severity_breakdown'].items():
            print(f"   {severity}: {count}")
        
        print(f"\n⏱️  Scan Times:")
        for scan_name, duration in results['scan_times'].items():
            print(f"   {scan_name}: {duration:.2f}s")
        
        print(f"\n🚀 Performance Metrics:")
        metrics = results['performance_metrics']
        print(f"   Average scan time: {metrics['average_scan_time']}s")
        print(f"   Parallel efficiency: {metrics['parallel_efficiency']}x")
        print(f"   Throughput: {metrics['findings_per_second']} findings/sec")


def main():
    """Main benchmark function"""
    parser = argparse.ArgumentParser(description="CloudGuard Performance Benchmark")
    parser.add_argument("--account-size", choices=["small", "medium", "large", "enterprise"], 
                       default="medium", help="Simulated account size")
    parser.add_argument("--workers", type=int, default=8, help="Number of parallel workers")
    parser.add_argument("--output", help="Output file for results (JSON)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Account size configurations
    account_configs = {
        "small": {"buckets": 10, "users": 5, "sgs": 20, "rds": 2, "lambda": 10},
        "medium": {"buckets": 100, "users": 50, "sgs": 200, "rds": 20, "lambda": 100},
        "large": {"buckets": 500, "users": 200, "sgs": 1000, "rds": 100, "lambda": 500},
        "enterprise": {"buckets": 1000, "users": 500, "sgs": 2000, "rds": 200, "lambda": 1000}
    }
    
    # Update mock data based on account size
    config = account_configs[args.account_size]
    global MOCK_S3_BUCKETS, MOCK_IAM_USERS, MOCK_SECURITY_GROUPS, MOCK_RDS_INSTANCES, MOCK_LAMBDA_FUNCTIONS
    
    MOCK_S3_BUCKETS = [{"Name": f"test-bucket-{i}"} for i in range(config["buckets"])]
    MOCK_IAM_USERS = [{"UserName": f"user-{i}"} for i in range(config["users"])]
    MOCK_SECURITY_GROUPS = [
        {
            "GroupId": f"sg-{i:08d}",
            "GroupName": f"test-sg-{i}",
            "IpPermissions": [
                {
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                }
            ]
        } for i in range(config["sgs"])
    ]
    MOCK_RDS_INSTANCES = [
        {
            "DBInstanceIdentifier": f"test-db-{i}",
            "PubliclyAccessible": True,
            "StorageEncrypted": False,
            "MultiAZ": False
        } for i in range(config["rds"])
    ]
    MOCK_LAMBDA_FUNCTIONS = [
        {
            "FunctionName": f"test-function-{i}",
            "Runtime": "python3.6" if i % 2 == 0 else "python3.11"
        } for i in range(config["lambda"])
    ]
    
    # Run benchmark
    scanner = MockAWSScanner(workers=args.workers)
    results = scanner.run_benchmark(args.account_size)
    
    # Print results
    scanner.print_results(results)
    
    # Save results if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n💾 Results saved to: {args.output}")
    
    # Performance recommendations
    print(f"\n💡 Performance Recommendations:")
    if results['total_duration'] > 300:  # 5 minutes
        print("   ⚠️  Consider increasing workers for faster scanning")
    if results['performance_metrics']['parallel_efficiency'] < 2:
        print("   ⚠️  Low parallel efficiency - check for I/O bottlenecks")
    if results['total_findings'] > 1000:
        print("   ⚠️  High finding count - consider filtering or pagination")
    
    print(f"\n✅ Benchmark complete!")


if __name__ == "__main__":
    main()
