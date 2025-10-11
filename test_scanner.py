"""
Unit tests for CloudGuard Enhanced scanner
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone
import json

from cg import AWSScanner, Finding, Severity, SecurityScoreCalculator, ReportGenerator


class TestAWSScanner:
    """Test cases for AWSScanner class"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.mock_session = Mock()
        self.mock_session.client.return_value = Mock()
        self.scanner = AWSScanner(session=self.mock_session, verbose=True)
        self.scanner.account_id = "123456789012"
    
    def test_scanner_initialization(self):
        """Test scanner initialization"""
        assert self.scanner.account_id == "123456789012"
        assert self.scanner.verbose is True
        assert self.scanner.max_workers == 8
    
    def test_make_finding(self):
        """Test finding creation"""
        finding = self.scanner._make_finding(
            id="test-finding",
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            resource_type="Test Resource",
            resource_id="test-resource",
            remediation="Test remediation",
            risk_score=75
        )
        
        assert finding.id == "test-finding"
        assert finding.title == "Test Finding"
        assert finding.severity == Severity.HIGH
        assert finding.risk_score == 75
        assert finding.detected_at is not None
    
    @patch('cg.AWSClientManager.get_client')
    def test_scan_s3_buckets_no_issues(self, mock_get_client):
        """Test S3 scanning with no issues"""
        mock_s3 = Mock()
        mock_s3.list_buckets.return_value = {"Buckets": []}
        mock_get_client.return_value = mock_s3
        
        findings = self.scanner.scan_s3_buckets()
        assert len(findings) == 0
    
    @patch('cg.AWSClientManager.get_client')
    def test_scan_s3_buckets_public_access(self, mock_get_client):
        """Test S3 scanning with public access issues"""
        mock_s3 = Mock()
        mock_s3.list_buckets.return_value = {
            "Buckets": [{"Name": "test-bucket"}]
        }
        mock_s3.get_public_access_block.side_effect = Exception("No public access block")
        mock_get_client.return_value = mock_s3
        
        findings = self.scanner.scan_s3_buckets()
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "public access" in findings[0].title.lower()
    
    @patch('cg.AWSClientManager.get_client')
    def test_scan_iam_root_mfa_disabled(self, mock_get_client):
        """Test IAM scanning with root MFA disabled"""
        mock_iam = Mock()
        mock_iam.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 0}
        }
        mock_iam.list_users.return_value = {"Users": []}
        mock_get_client.return_value = mock_iam
        
        findings = self.scanner.scan_iam()
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "root" in findings[0].title.lower()
    
    @patch('cg.AWSClientManager.get_client')
    def test_scan_ec2_sgs_public_access(self, mock_get_client):
        """Test EC2 security group scanning with public access"""
        mock_ec2 = Mock()
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{
                "GroupId": "sg-12345678",
                "GroupName": "test-sg",
                "IpPermissions": [{
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                }]
            }]
        }
        mock_get_client.return_value = mock_ec2
        
        findings = self.scanner.scan_ec2_sgs()
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "public" in findings[0].title.lower()
    
    def test_skip_services(self):
        """Test service skipping functionality"""
        scanner = AWSScanner(session=self.mock_session, skip_services=["s3", "iam"])
        assert "s3" in scanner.skip_services
        assert "iam" in scanner.skip_services


class TestSecurityScoreCalculator:
    """Test cases for SecurityScoreCalculator class"""
    
    def test_calculate_score_no_findings(self):
        """Test score calculation with no findings"""
        score = SecurityScoreCalculator.calculate([])
        assert score["score"] == 100
        assert score["grade"] == "A"
        assert score["total"] == 0
    
    def test_calculate_score_critical_findings(self):
        """Test score calculation with critical findings"""
        findings = [
            Finding(
                id="test-1",
                title="Test Critical",
                description="Test",
                severity=Severity.CRITICAL,
                resource_type="Test",
                resource_id="test",
                remediation="Test",
                risk_score=95,
                detected_at=datetime.now(timezone.utc).isoformat(),
                metadata={}
            )
        ]
        score = SecurityScoreCalculator.calculate(findings)
        assert score["score"] == 85  # 100 - 15
        assert score["grade"] == "B"
        assert score["counts"]["CRITICAL"] == 1
    
    def test_calculate_score_multiple_severities(self):
        """Test score calculation with multiple severity levels"""
        findings = [
            Finding(
                id="test-1",
                title="Test Critical",
                description="Test",
                severity=Severity.CRITICAL,
                resource_type="Test",
                resource_id="test",
                remediation="Test",
                risk_score=95,
                detected_at=datetime.now(timezone.utc).isoformat(),
                metadata={}
            ),
            Finding(
                id="test-2",
                title="Test High",
                description="Test",
                severity=Severity.HIGH,
                resource_type="Test",
                resource_id="test",
                remediation="Test",
                risk_score=80,
                detected_at=datetime.now(timezone.utc).isoformat(),
                metadata={}
            )
        ]
        score = SecurityScoreCalculator.calculate(findings)
        assert score["score"] == 75  # 100 - 15 - 10
        assert score["grade"] == "C"
        assert score["counts"]["CRITICAL"] == 1
        assert score["counts"]["HIGH"] == 1


class TestReportGenerator:
    """Test cases for ReportGenerator class"""
    
    def test_json_report(self):
        """Test JSON report generation"""
        findings = [
            Finding(
                id="test-1",
                title="Test Finding",
                description="Test",
                severity=Severity.HIGH,
                resource_type="Test",
                resource_id="test",
                remediation="Test",
                risk_score=80,
                detected_at=datetime.now(timezone.utc).isoformat(),
                metadata={}
            )
        ]
        score = {"score": 90, "grade": "A", "counts": {"HIGH": 1}, "total": 1}
        stats = {"scan_duration": 30.5}
        
        report = ReportGenerator.json_report(findings, score, stats)
        data = json.loads(report)
        
        assert data["score"]["score"] == 90
        assert data["score"]["grade"] == "A"
        assert len(data["findings"]) == 1
        assert data["metadata"]["scan_duration"] == 30.5
    
    def test_html_report(self):
        """Test HTML report generation"""
        findings = [
            Finding(
                id="test-1",
                title="Test Finding",
                description="Test",
                severity=Severity.HIGH,
                resource_type="Test",
                resource_id="test",
                remediation="Test",
                risk_score=80,
                detected_at=datetime.now(timezone.utc).isoformat(),
                metadata={}
            )
        ]
        score = {"score": 90, "grade": "A", "counts": {"HIGH": 1}, "total": 1}
        
        html = ReportGenerator.html_report(findings, score)
        assert "<html>" in html
        assert "Test Finding" in html
        assert "90" in html


class TestFinding:
    """Test cases for Finding class"""
    
    def test_finding_creation(self):
        """Test finding creation and serialization"""
        finding = Finding(
            id="test-finding",
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            resource_type="Test Resource",
            resource_id="test-resource",
            remediation="Test remediation",
            risk_score=75,
            detected_at=datetime.now(timezone.utc).isoformat(),
            metadata={"key": "value"}
        )
        
        assert finding.id == "test-finding"
        assert finding.severity == Severity.HIGH
        assert finding.risk_score == 75
        
        # Test serialization
        data = finding.to_dict()
        assert data["id"] == "test-finding"
        assert data["severity"] == "HIGH"
        assert data["metadata"]["key"] == "value"


if __name__ == "__main__":
    pytest.main([__file__])
