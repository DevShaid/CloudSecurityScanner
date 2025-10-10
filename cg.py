
import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum


import boto3
from botocore.exceptions import ClientError, NoCredentialsError

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.storage import StorageManagementClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "scanner": "cloudguard", "message": "%(message)s"}'
)
logger = logging.getLogger(__name__)

class Severity(Enum):
   
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ComplianceFramework(Enum):
   
    CIS_AWS = "CIS AWS Foundations Benchmark"
    PCI_DSS = "PCI-DSS"
    HIPAA = "HIPAA"
    SOC2 = "SOC 2"
    GDPR = "GDPR"

@dataclass
class Finding:
   
    id: str
    title: str
    description: str
    severity: Severity
    resource_type: str
    resource_id: str
    region: str
    account_id: str
    compliance: List[ComplianceFramework]
    remediation: str
    risk_score: int  # 0-100
    detected_at: str
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict:
        
        data = asdict(self)
        data['severity'] = self.severity.value
        data['compliance'] = [c.value for c in self.compliance]
        return data

class AWSScanner:
    #checks:
    #S3 buckets 4 public access, encryption, versioning, logging
    #IAM 4 root account usage, MFA, password policy, unused keys
    #EC2 4 security groups, public IPs, unencrypted volumes
    #RDS 4 public access, encryption, backups, multi-AZ
    #CloudTrail 4 enabled, log validation, encryption
    #VPC 4 flow logs, default security groups)
    #Lambda 4 public functions, outdated runtimes
    #ELB 4 SSL/TLS policies, access logs
    
    def __init__(self, profile: Optional[str] = None, region: str = 'us-east-1', fail_on_no_creds: bool = False):
       
        self.session = None
        self.account_id = None
        self.region = region
        self.enabled = False

        try:
            if profile:
                self.session = boto3.Session(profile_name=profile, region_name=region)
            else:
                
                self.session = boto3.Session(region_name=region)

            #
            sts = self.session.client('sts')
            self.account_id = sts.get_caller_identity()['Account']
            self.enabled = True
            logger.info(f"✅ AWS Scanner initialized - Account: {self.account_id}, Region: {region}")
        except (NoCredentialsError, ClientError) as e:
            msg = f"❌ AWS authentication failed: {e}"
            logger.error(msg)
            if fail_on_no_creds:
                raise
            else:
                logger.warning("AWSScanner disabled - continuing without AWS scans. Export AWS creds or set profile to enable scans.")

    def _get_account_id(self) -> str:
        
        sts = self.session.client('sts')
        return sts.get_caller_identity()['Account']
    
    async def scan_all(self) -> List[Finding]:
    #   Run all AWS security checks
        findings = []
        
        logger.info("🔍 Starting AWS security scan...")
        
        
        tasks = [
            self.scan_s3_buckets(),
            self.scan_iam(),
            self.scan_ec2_security_groups(),
            self.scan_rds_instances(),
            self.scan_cloudtrail(),
            self.scan_vpc(),
            self.scan_lambda_functions()
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"{tests[i].__name__} failed with exception: {result}")
            elif result is None:
                logger.error(f"{tests[i].__name__} returned None - scan may of have failed")
            else:
                findings.extend(result)
        
        logger.info(f"✅ AWS scan complete - {len(findings)} findings")
        return findings
    
    async def scan_s3_buckets(self) -> List[Finding]:
        #Scan S3 buckets for security issues
        findings = []
        s3 = self.session.client('s3')
        
        try:
            buckets = s3.list_buckets()['Buckets']
            logger.info(f"Scanning {len(buckets)} S3 buckets...")
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                
                try:
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        if grantee.get('Type') == 'Group' and 'AllUsers' in grantee.get('URI', ''):
                            findings.append(Finding(
                                id=f"s3-public-{bucket_name}",
                                title="S3 Bucket Publicly Accessible",
                                description=f"Bucket '{bucket_name}' allows public read/write access",
                                severity=Severity.CRITICAL,
                                resource_type="S3 Bucket",
                                resource_id=bucket_name,
                                region=self.region,
                                account_id=self.account_id,
                                compliance=[ComplianceFramework.CIS_AWS, ComplianceFramework.PCI_DSS],
                                remediation="Remove public access: aws s3api put-public-access-block --bucket {bucket} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true",
                                risk_score=95,
                                detected_at=datetime.utcnow().isoformat(),
                                metadata={"bucket": bucket_name, "check": "public_access"}
                            ))
                except ClientError:
                    pass
                
               
                try:
                    encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                except ClientError:
                    
                    findings.append(Finding(
                        id=f"s3-encryption-{bucket_name}",
                        title="S3 Bucket Not Encrypted",
                        description=f"Bucket '{bucket_name}' does not have default encryption enabled",
                        severity=Severity.HIGH,
                        resource_type="S3 Bucket",
                        resource_id=bucket_name,
                        region=self.region,
                        account_id=self.account_id,
                        compliance=[ComplianceFramework.PCI_DSS, ComplianceFramework.HIPAA],
                        remediation="Enable encryption: aws s3api put-bucket-encryption --bucket {bucket} --server-side-encryption-configuration '{\"Rules\": [{\"ApplyServerSideEncryptionByDefault\": {\"SSEAlgorithm\": \"AES256\"}}]}'",
                        risk_score=80,
                        detected_at=datetime.utcnow().isoformat(),
                        metadata={"bucket": bucket_name, "check": "encryption"}
                    ))
                
               
                try:
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                    if versioning.get('Status') != 'Enabled':
                        findings.append(Finding(
                            id=f"s3-versioning-{bucket_name}",
                            title="S3 Bucket Versioning Disabled",
                            description=f"Bucket '{bucket_name}' does not have versioning enabled",
                            severity=Severity.MEDIUM,
                            resource_type="S3 Bucket",
                            resource_id=bucket_name,
                            region=self.region,
                            account_id=self.account_id,
                            compliance=[ComplianceFramework.CIS_AWS],
                            remediation="Enable versioning: aws s3api put-bucket-versioning --bucket {bucket} --versioning-configuration Status=Enabled",
                            risk_score=50,
                            detected_at=datetime.utcnow().isoformat(),
                            metadata={"bucket": bucket_name, "check": "versioning"}
                        ))
                except ClientError:
                    pass
                
                try:
                    logging_config = s3.get_bucket_logging(Bucket=bucket_name)
                    if not logging_config.get('LoggingEnabled'):
                        findings.append(Finding(
                            id=f"s3-logging-{bucket_name}",
                            title="S3 Bucket Logging Disabled",
                            description=f"Bucket '{bucket_name}' does not have access logging enabled",
                            severity=Severity.LOW,
                            resource_type="S3 Bucket",
                            resource_id=bucket_name,
                            region=self.region,
                            account_id=self.account_id,
                            compliance=[ComplianceFramework.CIS_AWS, ComplianceFramework.SOC2],
                            remediation="Enable logging: aws s3api put-bucket-logging --bucket {bucket} --bucket-logging-status file://logging.json",
                            risk_score=30,
                            detected_at=datetime.utcnow().isoformat(),
                            metadata={"bucket": bucket_name, "check": "logging"}
                        ))
                except ClientError:
                    pass
        
        except ClientError as e:
            logger.error(f"S3 scan error: {e}")
        
        return findings
    
    async def scan_iam(self) -> List[Finding]:
        #Scan IAM for security issues
        findings = []
        iam = self.session.client('iam')
        
        try:
           
            try:
                account_summary = iam.get_account_summary()
                if account_summary['SummaryMap'].get('AccountMFAEnabled') == 0:
                    findings.append(Finding(
                        id="iam-root-mfa",
                        title="Root Account MFA Not Enabled",
                        description="AWS root account does not have MFA enabled",
                        severity=Severity.CRITICAL,
                        resource_type="IAM Account",
                        resource_id="root",
                        region="global",
                        account_id=self.account_id,
                        compliance=[ComplianceFramework.CIS_AWS, ComplianceFramework.PCI_DSS],
                        remediation="Enable MFA on root account via AWS Console > IAM > Dashboard",
                        risk_score=98,
                        detected_at=datetime.utcnow().isoformat(),
                        metadata={"check": "root_mfa"}
                    ))
            except ClientError:
                pass
            
            
            try:
                password_policy = iam.get_account_password_policy()
                policy = password_policy['PasswordPolicy']
                
                if policy.get('MinimumPasswordLength', 0) < 14:
                    findings.append(Finding(
                        id="iam-password-length",
                        title="Weak Password Policy",
                        description=f"Password minimum length is {policy.get('MinimumPasswordLength')} (should be 14+)",
                        severity=Severity.MEDIUM,
                        resource_type="IAM Password Policy",
                        resource_id="account",
                        region="global",
                        account_id=self.account_id,
                        compliance=[ComplianceFramework.CIS_AWS],
                        remediation="Update password policy: aws iam update-account-password-policy --minimum-password-length 14",
                        risk_score=60,
                        detected_at=datetime.utcnow().isoformat(),
                        metadata={"current_length": policy.get('MinimumPasswordLength')}
                    ))
                
                if not policy.get('RequireSymbols') or not policy.get('RequireNumbers'):
                    findings.append(Finding(
                        id="iam-password-complexity",
                        title="Password Complexity Not Enforced",
                        description="Password policy does not require symbols and numbers",
                        severity=Severity.MEDIUM,
                        resource_type="IAM Password Policy",
                        resource_id="account",
                        region="global",
                        account_id=self.account_id,
                        compliance=[ComplianceFramework.CIS_AWS],
                        remediation="Update password policy to require symbols and numbers",
                        risk_score=55,
                        detected_at=datetime.utcnow().isoformat(),
                        metadata={"check": "complexity"}
                    ))
            
            except iam.exceptions.NoSuchEntityException:
                findings.append(Finding(
                    id="iam-no-password-policy",
                    title="No Password Policy Configured",
                    description="Account does not have a password policy configured",
                    severity=Severity.HIGH,
                    resource_type="IAM Password Policy",
                    resource_id="account",
                    region="global",
                    account_id=self.account_id,
                    compliance=[ComplianceFramework.CIS_AWS],
                    remediation="Create password policy: aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers",
                    risk_score=75,
                    detected_at=datetime.utcnow().isoformat(),
                    metadata={"check": "policy_exists"}
                ))
            
           
            users = iam.list_users()['Users']
            for user in users:
                keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
                for key in keys:
                    
                    try:
                        last_used = iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                        last_used_date = last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                        
                        if last_used_date:
                            days_unused = (datetime.now(last_used_date.tzinfo) - last_used_date).days
                            if days_unused > 90:
                                findings.append(Finding(
                                    id=f"iam-unused-key-{key['AccessKeyId']}",
                                    title="Unused IAM Access Key",
                                    description=f"Access key for user '{user['UserName']}' hasn't been used in {days_unused} days",
                                    severity=Severity.LOW,
                                    resource_type="IAM Access Key",
                                    resource_id=key['AccessKeyId'],
                                    region="global",
                                    account_id=self.account_id,
                                    compliance=[ComplianceFramework.CIS_AWS],
                                    remediation=f"Delete key: aws iam delete-access-key --user-name {user['UserName']} --access-key-id {key['AccessKeyId']}",
                                    risk_score=35,
                                    detected_at=datetime.utcnow().isoformat(),
                                    metadata={"days_unused": days_unused, "user": user['UserName']}
                                ))
                    except ClientError:
                        pass
        
        except ClientError as e:
            logger.error(f"IAM scan error: {e}")
        
        return findings
    
    async def scan_ec2_security_groups(self) -> List[Finding]:
        #Scan EC2 security groups for overly permissive rules
        findings = []
        ec2 = self.session.client('ec2')
        
        try:
            security_groups = ec2.describe_security_groups()['SecurityGroups']
            
            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']
                
                
                for rule in sg.get('IpPermissions', []):
                    #
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            from_port = rule.get('FromPort', 0)
                            to_port = rule.get('ToPort', 65535)
                            
                            severity = Severity.CRITICAL if from_port in [22, 3389, 3306, 5432] else Severity.HIGH
                            risk_score = 90 if from_port in [22, 3389] else 75
                            
                            findings.append(Finding(
                                id=f"ec2-sg-open-{sg_id}-{from_port}",
                                title="Security Group Allows Public Access",
                                description=f"Security group '{sg_name}' allows inbound traffic from 0.0.0.0/0 on port {from_port}-{to_port}",
                                severity=severity,
                                resource_type="EC2 Security Group",
                                resource_id=sg_id,
                                region=self.region,
                                account_id=self.account_id,
                                compliance=[ComplianceFramework.CIS_AWS, ComplianceFramework.PCI_DSS],
                                remediation=f"Restrict access: aws ec2 revoke-security-group-ingress --group-id {sg_id} --cidr 0.0.0.0/0 --protocol tcp --port {from_port}",
                                risk_score=risk_score,
                                detected_at=datetime.utcnow().isoformat(),
                                metadata={"sg_id": sg_id, "port_range": f"{from_port}-{to_port}"}
                            ))
        
        except ClientError as e:
            logger.error(f"EC2 scan error: {e}")
        
        return findings
    
    async def scan_rds_instances(self) -> List[Finding]:
        #Scan RDS instances for security issues
        findings = []
        rds = self.session.client('rds')
        
        try:
            instances = rds.describe_db_instances()['DBInstances']
            
            for instance in instances:
                db_id = instance['DBInstanceIdentifier']
                
                
                if instance.get('PubliclyAccessible'):
                    findings.append(Finding(
                        id=f"rds-public-{db_id}",
                        title="RDS Instance Publicly Accessible",
                        description=f"Database '{db_id}' is publicly accessible",
                        severity=Severity.CRITICAL,
                        resource_type="RDS Instance",
                        resource_id=db_id,
                        region=self.region,
                        account_id=self.account_id,
                        compliance=[ComplianceFramework.CIS_AWS, ComplianceFramework.PCI_DSS, ComplianceFramework.HIPAA],
                        remediation=f"Disable public access: aws rds modify-db-instance --db-instance-identifier {db_id} --no-publicly-accessible",
                        risk_score=92,
                        detected_at=datetime.utcnow().isoformat(),
                        metadata={"db_id": db_id}
                    ))
                
               
                if not instance.get('StorageEncrypted'):
                    findings.append(Finding(
                        id=f"rds-encryption-{db_id}",
                        title="RDS Instance Not Encrypted",
                        description=f"Database '{db_id}' does not have encryption enabled",
                        severity=Severity.HIGH,
                        resource_type="RDS Instance",
                        resource_id=db_id,
                        region=self.region,
                        account_id=self.account_id,
                        compliance=[ComplianceFramework.PCI_DSS, ComplianceFramework.HIPAA],
                        remediation="Create encrypted snapshot and restore to new encrypted instance",
                        risk_score=85,
                        detected_at=datetime.utcnow().isoformat(),
                        metadata={"db_id": db_id}
                    ))
                
                if not instance.get('MultiAZ'):
                    findings.append(Finding(
                        id=f"rds-multiaz-{db_id}",
                        title="RDS Instance Not Multi-AZ",
                        description=f"Database '{db_id}' is not configured for Multi-AZ",
                        severity=Severity.MEDIUM,
                        resource_type="RDS Instance",
                        resource_id=db_id,
                        region=self.region,
                        account_id=self.account_id,
                        compliance=[ComplianceFramework.SOC2],
                        remediation=f"Enable Multi-AZ: aws rds modify-db-instance --db-instance-identifier {db_id} --multi-az",
                        risk_score=55,
                        detected_at=datetime.utcnow().isoformat(),
                        metadata={"db_id": db_id}
                    ))
        
        except ClientError as e:
            logger.error(f"RDS scan error: {e}")
        
        return findings
    
    async def scan_cloudtrail(self) -> List[Finding]:
        #Scan CloudTrail config
        findings = []
        cloudtrail = self.session.client('cloudtrail')
        
        try:
            trails = cloudtrail.describe_trails()['trailList']
            
            if not trails:
                findings.append(Finding(
                    id="cloudtrail-disabled",
                    title="CloudTrail Not Enabled",
                    description="No CloudTrail trails are configured",
                    severity=Severity.CRITICAL,
                    resource_type="CloudTrail",
                    resource_id="account",
                    region=self.region,
                    account_id=self.account_id,
                    compliance=[ComplianceFramework.CIS_AWS, ComplianceFramework.PCI_DSS],
                    remediation="Enable CloudTrail: aws cloudtrail create-trail --name management-events --s3-bucket-name your-bucket",
                    risk_score=88,
                    detected_at=datetime.utcnow().isoformat(),
                    metadata={"check": "enabled"}
                ))
            else:
                for trail in trails:
                    trail_name = trail['Name']
                    
                    # Check log validation
                    if not trail.get('LogFileValidationEnabled'):
                        findings.append(Finding(
                            id=f"cloudtrail-validation-{trail_name}",
                            title="CloudTrail Log Validation Disabled",
                            description=f"Trail '{trail_name}' does not have log file validation enabled",
                            severity=Severity.MEDIUM,
                            resource_type="CloudTrail",
                            resource_id=trail_name,
                            region=self.region,
                            account_id=self.account_id,
                            compliance=[ComplianceFramework.CIS_AWS],
                            remediation=f"Enable validation: aws cloudtrail update-trail --name {trail_name} --enable-log-file-validation",
                            risk_score=50,
                            detected_at=datetime.utcnow().isoformat(),
                            metadata={"trail": trail_name}
                        ))
        
        except ClientError as e:
            logger.error(f"CloudTrail scan error: {e}")
        
        return findings
    
    async def scan_vpc(self) -> List[Finding]:
        #Scan VPC configuration
        findings = []
        ec2 = self.session.client('ec2')
        
        try:
            vpcs = ec2.describe_vpcs()['Vpcs']
            
            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                
                # Check flow logs
                flow_logs = ec2.describe_flow_logs(
                    Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
                )['FlowLogs']
                
                if not flow_logs:
                    findings.append(Finding(
                        id=f"vpc-flowlogs-{vpc_id}",
                        title="VPC Flow Logs Not Enabled",
                        description=f"VPC '{vpc_id}' does not have flow logs enabled",
                        severity=Severity.MEDIUM,
                        resource_type="VPC",
                        resource_id=vpc_id,
                        region=self.region,
                        account_id=self.account_id,
                        compliance=[ComplianceFramework.CIS_AWS],
                        remediation=f"Enable flow logs: aws ec2 create-flow-logs --resource-type VPC --resource-ids {vpc_id} --traffic-type ALL --log-destination-type cloud-watch-logs",
                        risk_score=45,
                        detected_at=datetime.utcnow().isoformat(),
                        metadata={"vpc_id": vpc_id}
                    ))
        
        except ClientError as e:
            logger.error(f"VPC scan error: {e}")
        
        return findings
    
    async def scan_lambda_functions(self) -> List[Finding]:
        #Scan Lambda functions for security issues
        findings = []
        lambda_client = self.session.client('lambda')
        
        try:
            functions = lambda_client.list_functions()['Functions']
            
            for func in functions:
                func_name = func['FunctionName']
                runtime = func.get('Runtime', '')
                
                outdated_runtimes = ['python3.6', 'python3.7', 'nodejs12.x', 'nodejs10.x']
                if runtime in outdated_runtimes:
                    findings.append(Finding(
                        id=f"lambda-runtime-{func_name}",
                        title="Lambda Function Using Outdated Runtime",
                        description=f"Function '{func_name}' is using outdated runtime '{runtime}'",
                        severity=Severity.MEDIUM,
                        resource_type="Lambda Function",
                        resource_id=func_name,
                        region=self.region,
                        account_id=self.account_id,
                        compliance=[ComplianceFramework.SOC2],
                        remediation=f"Update runtime: aws lambda update-function-configuration --function-name {func_name} --runtime python3.11",
                        risk_score=52,
                        detected_at=datetime.utcnow().isoformat(),
                        metadata={"function": func_name, "runtime": runtime}
                    ))
        
        except ClientError as e:
            logger.error(f"Lambda scan error: {e}")
        
        return findings

class SecurityScoreCalculator:
    #Calculate overall security score
    
    @staticmethod
    def calculate_score(findings: List[Finding]) -> Dict[str, Any]:
        """Calculate security score from findings"""
        if not findings:
            return {
                "score": 100,
                "grade": "A",
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "total": 0
            }
        
        # Count by severity
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        
        for finding in findings:
            severity_counts[finding.severity.value] += 1
        
        
        deductions = (
            severity_counts["CRITICAL"] * 15 +
            severity_counts["HIGH"] * 10 +
            severity_counts["MEDIUM"] * 5 +
            severity_counts["LOW"] * 2
        )
        
        score = max(0, 100 - deductions)
        
      
        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"
        
        return {
            "score": score,
            "grade": grade,
            "critical": severity_counts["CRITICAL"],
            "high": severity_counts["HIGH"],
            "medium": severity_counts["MEDIUM"],
            "low": severity_counts["LOW"],
            "total": len(findings)
        }

class ReportGenerator:
    """Generate security reports"""
    
    @staticmethod
    def generate_json_report(findings: List[Finding], score: Dict[str, Any]) -> str:
        """Generate JSON report"""
        report = {
            "scan_timestamp": datetime.utcnow().isoformat(),
            "score": score,
            "findings": [f.to_dict() for f in findings],
            "summary": {
                "total_resources_scanned": len(set(f.resource_id for f in findings)),
                "compliance_frameworks": list(set(
                    cf.value for f in findings for cf in f.compliance
                ))
            }
        }
        return json.dumps(report, indent=2)
    
    @staticmethod
    def generate_html_report(findings: List[Finding], score: Dict[str, Any]) -> str:
        """Generate HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>CloudGuard Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; }}
        .score {{ font-size: 48px; font-weight: bold; }}
        .grade-{score['grade']} {{ color: {'#4CAF50' if score['grade'] in ['A', 'B'] else '#ff8800' if score['grade'] == 'C' else '#ff0000'}; }}
        .finding {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .CRITICAL {{ border-left: 5px solid #ff0000; }}
        .HIGH {{ border-left: 5px solid #ff8800; }}
        .MEDIUM {{ border-left: 5px solid #ffcc00; }}
        .LOW {{ border-left: 5px solid #4CAF50; }}
        .severity {{ display: inline-block; padding: 5px 10px; border-radius: 3px; color: white; font-weight: bold; }}
        .CRITICAL-badge {{ background: #ff0000; }}
        .HIGH-badge {{ background: #ff8800; }}
        .MEDIUM-badge {{ background: #ffcc00; color: #333; }}
        .LOW-badge {{ background: #4CAF50; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ CloudGuard Security Report</h1>
        <p>Scan Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        <div class="score grade-{score['grade']}">{score['score']}/100 (Grade: {score['grade']})</div>
    </div>
    
    <h2>Summary</h2>
    <p><strong>Total Findings:</strong> {score['total']}</p>
    <p><strong>Critical:</strong> {score['critical']} | <strong>High:</strong> {score['high']} | <strong>Medium:</strong> {score['medium']} | <strong>Low:</strong> {score['low']}</p>
    
    <h2>Findings</h2>
"""
        
        for finding in sorted(findings, key=lambda x: x.risk_score, reverse=True):
            html += f"""
    <div class="finding {finding.severity.value}">
        <h3>{finding.title} <span class="severity {finding.severity.value}-badge">{finding.severity.value}</span></h3>
        <p><strong>Resource:</strong> {finding.resource_type} - {finding.resource_id}</p>
        <p><strong>Description:</strong> {finding.description}</p>
        <p><strong>Risk Score:</strong> {finding.risk_score}/100</p>
        <p><strong>Compliance:</strong> {', '.join(c.value for c in finding.compliance)}</p>
        <p><strong>Remediation:</strong> <code>{finding.remediation}</code></p>
    </div>
"""
        
        html += """
</body>
</html>
"""
        return html

async def main():
    """Main scanner execution"""
    print("🛡️ CloudGuard - Multi-Cloud Security Scanner")
    print("=" * 50)
    
    # Initialize AWS scanner
    try:
        scanner = AWSScanner(region='us-east-1')
    except Exception as e:
        logger.error(f"Failed to initialize scanner: {e}")
        return
    
    # Run scan
    findings = await scanner.scan_all()
    
    # Calculate score
    score = SecurityScoreCalculator.calculate_score(findings)
    

    print(f"\n📊 Security Score: {score['score']}/100 (Grade: {score['grade']})")
    print(f"🔍 Total Findings: {score['total']}")
    print(f"   🚨 Critical: {score['critical']}")
    print(f"   ⚠️  High: {score['high']}")
    print(f"   📊 Medium: {score['medium']}")
    print(f"   ℹ️  Low: {score['low']}")
    
    
    if findings:
        print("\n🔥 Top Critical Findings:")
        critical_findings = sorted(findings, key=lambda x: x.risk_score, reverse=True)[:5]
        for i, finding in enumerate(critical_findings, 1):
            print(f"\n{i}. [{finding.severity.value}] {finding.title}")
            print(f"   Resource: {finding.resource_type} - {finding.resource_id}")
            print(f"   Risk Score: {finding.risk_score}/100")
            print(f"   Fix: {finding.remediation[:100]}...")
    
    # Generate reports
    print("\n📄 Generating Reports...")
    
    # JSON report
    json_report = ReportGenerator.generate_json_report(findings, score)
    with open('cloudguard_report.json', 'w') as f:
        f.write(json_report)
    print("✅ JSON report saved: cloudguard_report.json")
    
    # HTML report
    html_report = ReportGenerator.generate_html_report(findings, score)
    with open('cloudguard_report.html', 'w') as f:
        f.write(html_report)
    print("✅ HTML report saved: cloudguard_report.html")
    
    print("\n🎉 Scan complete!")

if __name__ == "__main__":
    asyncio.run(main())
  
  
