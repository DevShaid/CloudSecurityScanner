
import pytest
import boto3
from moto import mock_s3, mock_iam, mock_ec2, mock_rds, mock_lambda
from unittest.mock import patch
import json

from cg import AWSScanner, Finding, Severity


class TestAWSIntegration:
   
    
    def setup_method(self):
       
        self.scanner = AWSScanner(verbose=True)
        self.scanner.account_id = "123456789012"
    
    @mock_s3
    def test_s3_integration_public_bucket(self):
      
        s3 = boto3.client('s3', region_name='us-east-1')
        
       
        bucket_name = "test-public-bucket"
        s3.create_bucket(Bucket=bucket_name)
        
       
        with patch.object(s3, 'get_public_access_block', side_effect=Exception("No public access block")):
            findings = self.scanner.scan_s3_buckets()
            
            # Should find public access issue
            assert len(findings) > 0
            public_findings = [f for f in findings if "public" in f.title.lower()]
            assert len(public_findings) > 0
            assert public_findings[0].severity == Severity.CRITICAL
    
    @mock_s3
    def test_s3_integration_encrypted_bucket(self):
        """Test S3 integration with encrypted bucket"""
        s3 = boto3.client('s3', region_name='us-east-1')
        bucket_name = "test-encrypted-bucket"
        s3.create_bucket(Bucket=bucket_name)
        
        # Enable encryption
        s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    }
                ]
            }
        )
        
        # Set public access block
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        
        findings = self.scanner.scan_s3_buckets()
        
        # Should not find encryption issues
        encryption_findings = [f for f in findings if "encryption" in f.title.lower()]
        assert len(encryption_findings) == 0
    
    @mock_iam
    def test_iam_integration_root_mfa(self):
        """Test IAM integration with root MFA"""
        iam = boto3.client('iam', region_name='us-east-1')
        
        # Mock account summary without MFA
        with patch.object(iam, 'get_account_summary', return_value={
            'SummaryMap': {'AccountMFAEnabled': 0}
        }):
            findings = self.scanner.scan_iam()
            
            # Should find root MFA issue
            root_findings = [f for f in findings if "root" in f.title.lower() and "mfa" in f.title.lower()]
            assert len(root_findings) > 0
            assert root_findings[0].severity == Severity.CRITICAL
    
    @mock_iam
    def test_iam_integration_password_policy(self):
        """Test IAM integration with password policy"""
        iam = boto3.client('iam', region_name='us-east-1')
        
        # Create weak password policy
        iam.update_account_password_policy(
            MinimumPasswordLength=8,
            RequireSymbols=False,
            RequireNumbers=False
        )
        
        findings = self.scanner.scan_iam()
        
        # Should find password policy issues
        password_findings = [f for f in findings if "password" in f.title.lower()]
        assert len(password_findings) > 0
    
    @mock_ec2
    def test_ec2_integration_security_groups(self):
        """Test EC2 integration with security groups"""
        ec2 = boto3.client('ec2', region_name='us-east-1')
        
        # Create security group with public access
        response = ec2.create_security_group(
            GroupName='test-sg',
            Description='Test security group'
        )
        sg_id = response['GroupId']
        
        # Add rule allowing SSH from anywhere
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }
            ]
        )
        
        findings = self.scanner.scan_ec2_sgs()
        
        # Should find public access issue
        public_findings = [f for f in findings if "public" in f.title.lower()]
        assert len(public_findings) > 0
        assert public_findings[0].severity == Severity.CRITICAL
    
    @mock_rds
    def test_rds_integration_public_instance(self):
        """Test RDS integration with public instance"""
        rds = boto3.client('rds', region_name='us-east-1')
        
        # Create RDS instance (moto doesn't support all parameters)
        with patch.object(rds, 'describe_db_instances', return_value={
            'DBInstances': [{
                'DBInstanceIdentifier': 'test-db',
                'PubliclyAccessible': True,
                'StorageEncrypted': False,
                'MultiAZ': False
            }]
        }):
            findings = self.scanner.scan_rds()
            
            # Should find public access and encryption issues
            public_findings = [f for f in findings if "public" in f.title.lower()]
            encryption_findings = [f for f in findings if "encryption" in f.title.lower()]
            
            assert len(public_findings) > 0
            assert len(encryption_findings) > 0
    
    @mock_lambda
    def test_lambda_integration_deprecated_runtime(self):
        """Test Lambda integration with deprecated runtime"""
        lambda_client = boto3.client('lambda', region_name='us-east-1')
        
        # Create Lambda function with deprecated runtime
        with patch.object(lambda_client, 'list_functions', return_value={
            'Functions': [{
                'FunctionName': 'test-function',
                'Runtime': 'python3.6',
                'LastModified': '2023-01-01T00:00:00Z'
            }]
        }):
            findings = self.scanner.scan_lambda_functions()
            
            # Should find deprecated runtime issue
            runtime_findings = [f for f in findings if "runtime" in f.title.lower()]
            assert len(runtime_findings) > 0
            assert runtime_findings[0].severity == Severity.HIGH
    
    def test_scanner_error_handling(self):
        """Test scanner error handling"""
        # Test with invalid credentials
        with patch('cg.AWSClientManager.get_client', side_effect=Exception("Invalid credentials")):
            findings = self.scanner.scan_s3_buckets()
            # Should return empty list on error
            assert len(findings) == 0
    
    def test_parallel_scanning(self):
        """Test parallel scanning functionality"""
        # Mock all scan methods to return findings
        with patch.object(self.scanner, 'scan_s3_buckets', return_value=[
            Finding(
                id="test-1",
                title="Test S3 Finding",
                description="Test",
                severity=Severity.HIGH,
                resource_type="S3",
                resource_id="test",
                remediation="Test",
                risk_score=80,
                detected_at="2023-01-01T00:00:00Z",
                metadata={}
            )
        ]), \
        patch.object(self.scanner, 'scan_iam', return_value=[]), \
        patch.object(self.scanner, 'scan_ec2_sgs', return_value=[]), \
        patch.object(self.scanner, 'scan_rds', return_value=[]), \
        patch.object(self.scanner, 'scan_lambda_functions', return_value=[]):
            
            findings = self.scanner.run_all()
            
            # Should have findings from S3 scan
            assert len(findings) > 0
            assert findings[0].title == "Test S3 Finding"
    
    def test_skip_services(self):
        """Test service skipping functionality"""
        scanner = AWSScanner(skip_services=["s3", "iam"])
        
        with patch.object(scanner, 'scan_s3_buckets', return_value=[]) as mock_s3, \
             patch.object(scanner, 'scan_iam', return_value=[]) as mock_iam, \
             patch.object(scanner, 'scan_ec2_sgs', return_value=[]) as mock_ec2:
            
            scanner.run_all()
            
            # S3 and IAM should be skipped
            mock_s3.assert_not_called()
            mock_iam.assert_not_called()
            # EC2 should still be called
            mock_ec2.assert_called_once()
    
    def test_finding_serialization(self):
        """Test finding serialization for reports"""
        finding = Finding(
            id="test-finding",
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            resource_type="Test Resource",
            resource_id="test-resource",
            remediation="Test remediation",
            risk_score=75,
            detected_at="2023-01-01T00:00:00Z",
            metadata={"key": "value"}
        )
        
        # Test to_dict method
        data = finding.to_dict()
        assert data["id"] == "test-finding"
        assert data["severity"] == "HIGH"
        assert data["metadata"]["key"] == "value"
        
        # Test JSON serialization
        json_str = json.dumps(data)
        parsed = json.loads(json_str)
        assert parsed["title"] == "Test Finding"


if __name__ == "__main__":
    pytest.main([__file__])
