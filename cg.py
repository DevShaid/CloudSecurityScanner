#!/usr/bin/env python3
"""
CloudGuard Enhanced - AWS Security Scanner
Checks for S3 buckets, IAM policies, EC2 security groups, RDS instances,
CloudTrail, EBS volumes, KMS keys, VPC flow logs, Secrets Manager,
Lambda functions, and yeah yeah you get the gist :)
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import List, Dict, Any, Optional, Iterator, Callable
import json
import logging
import argparse
import sys
import boto3
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError, BotoCoreError
from botocore.config import Config
import time
import random
from functools import wraps


logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","scanner":"cloudguard","msg":"%(message)s"}'
)
logger = logging.getLogger(__name__)


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class Finding:
    id: str
    title: str
    description: str
    severity: Severity
    resource_type: str
    resource_id: str
    remediation: str
    risk_score: int
    detected_at: str
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d

def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def retry_with_backoff(max_attempts: int = 3, base_delay: float = 1.0, max_delay: float = 60.0):

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except (ClientError, EndpointConnectionError, BotoCoreError) as e:
                    last_exception = e
                    
                   
                    if hasattr(e, 'response') and e.response.get('Error', {}).get('Code') in [
                        'AccessDenied', 'UnauthorizedOperation', 'InvalidUserID.NotFound',
                        'NoSuchEntity', 'ResourceNotFoundException'
                    ]:
                        raise e
                    
                    if attempt < max_attempts - 1:
                        delay = min(base_delay * (2 ** attempt) + random.uniform(0, 1), max_delay)
                        logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {delay:.2f}s...")
                        time.sleep(delay)
            else:
                        logger.error(f"All {max_attempts} attempts failed for {func.__name__}")
                        
            raise last_exception
        return wrapper
    return decorator


class AWSClientManager:
   
    
    @staticmethod
    def get_client(service: str, session: boto3.Session, region: str = None) -> Any:
        
        config = Config(
            retries={
                'max_attempts': 3,
                'mode': 'adaptive'
            },
            max_pool_connections=50
        )
        
        if region:
            return session.client(service, region_name=region, config=config)
        return session.client(service, config=config)

class Paginator:
   
    
    @staticmethod
    def paginate(client, operation: str, **kwargs) -> Iterator[Dict[str, Any]]:
        
        try:
            paginator = client.get_paginator(operation)
            for page in paginator.paginate(**kwargs):
                yield page
        except ClientError as e:
            logger.warning(f"Pagination failed for {operation}: {e}")
            
            try:
                response = getattr(client, operation.replace('_', ''))(**kwargs)
                yield response
            except Exception:
                pass

    @staticmethod
    def get_all_items(client, operation: str, key: str, **kwargs) -> List[Dict[str, Any]]:
        """Get all items from a paginated AWS API response"""
        items = []
        for page in Paginator.paginate(client, operation, **kwargs):
            items.extend(page.get(key, []))
        return items


class AWSScanner:
    def __init__(self, session: Optional[boto3.Session] = None, profile: Optional[str] = None, 
                 region: str = "us-east-1", max_workers: int = 8, verbose: bool = False,
                 skip_services: List[str] = None):
        self.region = region
        self.max_workers = max_workers
        self.verbose = verbose
        self.session = session
        self.skip_services = skip_services or []
        
        if not self.session:
            try:
                self.session = boto3.Session(profile_name=profile) if profile else boto3.Session(region_name=region)
            except Exception as e:
                logger.error(f"Failed creating session: {e}")
                raise
                
        try:
            sts = AWSClientManager.get_client("sts", self.session)
            identity = sts.get_caller_identity()
            self.account_id = identity["Account"]
            logger.info(f"AWSScanner initialized (account={self.account_id}, region={self.region}, workers={max_workers})")
        except (NoCredentialsError, ClientError, EndpointConnectionError) as e:
            logger.error(f"Failed to connect to AWS: {e}")
            raise

    def _make_finding(self, **kwargs) -> Finding:
        return Finding(detected_at=utcnow_iso(), **kwargs)

   
    @retry_with_backoff()
    def scan_s3_buckets(self) -> List[Finding]:
        findings = []
        s3 = AWSClientManager.get_client("s3", self.session)
        
        try:
            buckets = s3.list_buckets().get("Buckets", [])
            if self.verbose:
                logger.info(f"Scanning {len(buckets)} S3 buckets...")
                
            for bucket in buckets:
                name = bucket["Name"]
                
                
                try:
                    pab = s3.get_public_access_block(Bucket=name)
                    config = pab.get("PublicAccessBlockConfiguration", {})
                    if not all([config.get("BlockPublicAcls", False), 
                              config.get("BlockPublicPolicy", False),
                              config.get("IgnorePublicAcls", False),
                              config.get("RestrictPublicBuckets", False)]):
                        findings.append(self._make_finding(
                            id=f"s3-public-access-{name}",
                            title="S3 Bucket Public Access Not Blocked",
                            description=f"Bucket '{name}' allows public access",
                            severity=Severity.CRITICAL,
                            resource_type="S3 Bucket",
                            resource_id=name,
                            remediation=f"aws s3api put-public-access-block --bucket {name} --public-access-block-configuration BlockPublicAcls=true,BlockPublicPolicy=true,IgnorePublicAcls=true,RestrictPublicBuckets=true",
                            risk_score=95,
                            metadata={"bucket": name}
                        ))
                except ClientError:
                   
                    findings.append(self._make_finding(
                        id=f"s3-public-access-{name}",
                        title="S3 Bucket Public Access Block Not Configured",
                        description=f"Bucket '{name}' does not have public access block configured",
                        severity=Severity.CRITICAL,
                        resource_type="S3 Bucket",
                        resource_id=name,
                        remediation=f"aws s3api put-public-access-block --bucket {name} --public-access-block-configuration BlockPublicAcls=true,BlockPublicPolicy=true,IgnorePublicAcls=true,RestrictPublicBuckets=true",
                        risk_score=95,
                        metadata={"bucket": name}
                    ))
                
              
                try:
                    acl = s3.get_bucket_acl(Bucket=name)
                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        if grantee.get("Type") == "Group" and "AllUsers" in grantee.get("URI", ""):
                            findings.append(self._make_finding(
                                id=f"s3-legacy-acl-{name}",
                                title="S3 Bucket Has Legacy Public ACL",
                                description=f"Bucket '{name}' has legacy public ACL (AllUsers) grant",
                                severity=Severity.CRITICAL,
                                resource_type="S3 Bucket",
                                resource_id=name,
                                remediation=f"aws s3api put-bucket-acl --bucket {name} --acl private",
                                risk_score=95,
                                metadata={"bucket": name, "grant_type": "AllUsers"}
                            ))
                            break
                except ClientError:
                    pass
                
                
                try:
                    s3.get_bucket_encryption(Bucket=name)
                except ClientError:
                    findings.append(self._make_finding(
                        id=f"s3-encryption-{name}",
                        title="S3 Bucket Not Encrypted",
                        description=f"Bucket '{name}' has no default encryption",
                        severity=Severity.HIGH,
                        resource_type="S3 Bucket",
                        resource_id=name,
                        remediation=f"aws s3api put-bucket-encryption --bucket {name} --server-side-encryption-configuration '{{\"Rules\":[{{\"ApplyServerSideEncryptionByDefault\":{{\"SSEAlgorithm\":\"AES256\"}}}}]}}'",
                        risk_score=85,
                        metadata={"bucket": name}
                    ))
                
                
                try:
                    versioning = s3.get_bucket_versioning(Bucket=name)
                    if versioning.get("Status") != "Enabled":
                        findings.append(self._make_finding(
                            id=f"s3-versioning-{name}",
                            title="S3 Bucket Versioning Disabled",
                            description=f"Bucket '{name}' does not have versioning enabled",
                            severity=Severity.MEDIUM,
                            resource_type="S3 Bucket",
                            resource_id=name,
                            remediation=f"aws s3api put-bucket-versioning --bucket {name} --versioning-configuration Status=Enabled",
                            risk_score=50,
                            metadata={"bucket": name}
                        ))
                    
                   
                    if versioning.get("MFADelete") != "Enabled":
                        
                        try:
                            tags = s3.get_bucket_tagging(Bucket=name)
                            tag_dict = {tag["Key"]: tag["Value"] for tag in tags.get("TagSet", [])}
                            if any(keyword in tag_dict.get("Environment", "").lower() 
                                  for keyword in ["prod", "production"]) or \
                               any(keyword in name.lower() for keyword in ["prod", "production", "backup", "log"]):
                                findings.append(self._make_finding(
                                    id=f"s3-mfa-delete-{name}",
                                    title="S3 Bucket MFA Delete Disabled",
                                    description=f"Sensitive bucket '{name}' does not have MFA delete enabled",
                                    severity=Severity.HIGH,
                            resource_type="S3 Bucket",
                                    resource_id=name,
                                    remediation=f"aws s3api put-bucket-versioning --bucket {name} --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa 'arn:aws:iam::ACCOUNT:mfa/root-account-mfa-device TOKEN_CODE'",
                                    risk_score=75,
                                    metadata={"bucket": name, "sensitive": True}
                                ))
                        except ClientError:
                            pass  
                            
                except ClientError:
                    pass
        
                if self.verbose:
                    bucket_findings = len([f for f in findings if f.resource_id == name])
                    if bucket_findings > 0:
                        logger.debug(f"Found {bucket_findings} issues in bucket {name}")
                    
        except ClientError as e:
            logger.error(f"S3 scan failed: {e}")
        
        return findings
    
   
    @retry_with_backoff()
    def scan_iam(self) -> List[Finding]:
        findings = []
        iam = AWSClientManager.get_client("iam", self.session)
        
      
        try:
            summary = iam.get_account_summary().get("SummaryMap", {})
            if summary.get("AccountMFAEnabled", 0) == 0:
                findings.append(self._make_finding(
                    id="iam-root-mfa",
                    title="Root Account MFA Not Enabled",
                    description="Root account does not have MFA enabled",
                    severity=Severity.CRITICAL,
                    resource_type="IAM Account",
                    resource_id="root",
                    remediation="Enable MFA on root account in AWS console",
                    risk_score=98,
                    metadata={}
                ))
        except ClientError:
            pass
            
        
        try:
            password_policy = iam.get_account_password_policy()
            policy = password_policy.get("PasswordPolicy", {})
            
            if policy.get("MinimumPasswordLength", 0) < 14:
                findings.append(self._make_finding(
                    id="iam-password-length",
                    title="Weak Password Policy",
                    description=f"Password minimum length is {policy.get('MinimumPasswordLength')} (should be 14+)",
                    severity=Severity.MEDIUM,
                    resource_type="IAM Password Policy",
                    resource_id="account",
                    remediation="aws iam update-account-password-policy --minimum-password-length 14",
                    risk_score=60,
                    metadata={"current_length": policy.get("MinimumPasswordLength")}
                ))
                
            if not policy.get("RequireSymbols") or not policy.get("RequireNumbers"):
                findings.append(self._make_finding(
                    id="iam-password-complexity",
                    title="Password Complexity Not Enforced",
                    description="Password policy does not require symbols and numbers",
                    severity=Severity.MEDIUM,
                    resource_type="IAM Password Policy",
                    resource_id="account",
                    remediation="aws iam update-account-password-policy --require-symbols --require-numbers",
                    risk_score=55,
                    metadata={"check": "complexity"}
                ))
            
        except iam.exceptions.NoSuchEntityException:
            findings.append(self._make_finding(
                id="iam-no-password-policy",
                title="No Password Policy Configured",
                description="Account does not have a password policy configured",
                severity=Severity.HIGH,
                resource_type="IAM Password Policy",
                resource_id="account",
                remediation="aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers",
                risk_score=75,
                metadata={"check": "policy_exists"}
            ))
        except ClientError:
            pass
            

        try:
            users = Paginator.get_all_items(iam, "list_users", "Users")
            if self.verbose:
                logger.info(f"Scanning {len(users)} IAM users...")
           
            for user in users:
                uname = user["UserName"]
                try:
                    keys = Paginator.get_all_items(iam, "list_access_keys", "AccessKeyMetadata", UserName=uname)
                    for key in keys:
                        try:
                            last_used = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"]).get("AccessKeyLastUsed", {})
                            last_date = last_used.get("LastUsedDate")
                            if last_date:
                                days_unused = (datetime.now(timezone.utc) - last_date).days
                            if days_unused > 90:
                                    findings.append(self._make_finding(
                                    id=f"iam-unused-key-{key['AccessKeyId']}",
                                    title="Unused IAM Access Key",
                                        description=f"User {uname} has unused access key for {days_unused} days",
                                    severity=Severity.LOW,
                                    resource_type="IAM Access Key",
                                        resource_id=key["AccessKeyId"],
                                        remediation=f"aws iam delete-access-key --user-name {uname} --access-key-id {key['AccessKeyId']}",
                                        risk_score=35,
                                        metadata={"user": uname, "days_unused": days_unused}
                                    ))
                        except ClientError:
                            continue
                except ClientError:
                    continue
        
        except ClientError as e:
            logger.error(f"IAM scan failed: {e}")
        
        return findings
    
    
    @retry_with_backoff()
    def scan_ec2_sgs(self) -> List[Finding]:
        findings = []
        ec2 = AWSClientManager.get_client("ec2", self.session)
        
        try:
            security_groups = ec2.describe_security_groups().get("SecurityGroups", [])
            if self.verbose:
                logger.info(f"Scanning {len(security_groups)} security groups...")
                
            for sg in security_groups:
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", "<no-name>")
                
                for perm in sg.get("IpPermissions", []):
                    from_port = perm.get("FromPort")
                    to_port = perm.get("ToPort", from_port)
                    protocol = perm.get("IpProtocol", "tcp")
                    
                   
                    for ipr in perm.get("IpRanges", []):
                        if ipr.get("CidrIp") == "0.0.0.0/0":
                            severity = Severity.CRITICAL if from_port in (22, 3389) else Severity.HIGH
                            risk = 90 if from_port in (22, 3389) else 75
                            findings.append(self._make_finding(
                                id=f"ec2-sg-ipv4-open-{sg_id}-{from_port}",
                                title="Security Group Allows Public IPv4 Traffic",
                                description=f"{sg_name} ({sg_id}) allows 0.0.0.0/0 on {protocol} port {from_port}-{to_port}",
                                severity=severity,
                                resource_type="Security Group",
                                resource_id=sg_id,
                                remediation=f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol {protocol} --port {from_port}-{to_port} --cidr 0.0.0.0/0",
                                risk_score=risk,
                                metadata={"sg_name": sg_name, "port_range": f"{from_port}-{to_port}", "protocol": protocol, "type": "ipv4"}
                            ))
                    
                    
                    for ipv6r in perm.get("Ipv6Ranges", []):
                        if ipv6r.get("CidrIpv6") == "::/0":
                            severity = Severity.CRITICAL if from_port in (22, 3389) else Severity.HIGH
                            risk = 90 if from_port in (22, 3389) else 75
                            findings.append(self._make_finding(
                                id=f"ec2-sg-ipv6-open-{sg_id}-{from_port}",
                                title="Security Group Allows Public IPv6 Traffic",
                                description=f"{sg_name} ({sg_id}) allows ::/0 on {protocol} port {from_port}-{to_port}",
                                severity=severity,
                                resource_type="Security Group",
                                resource_id=sg_id,
                                remediation=f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol {protocol} --port {from_port}-{to_port} --ipv6-cidr ::/0",
                                risk_score=risk,
                                metadata={"sg_name": sg_name, "port_range": f"{from_port}-{to_port}", "protocol": protocol, "type": "ipv6"}
                            ))
                    
                   
                    for prefix_list in perm.get("PrefixListIds", []):
                        # Note: i can't easily determine if a prefix list is overly permissive
                        # without additional API calls but can still flag it for review
                        if self.verbose:
                            logger.debug(f"Security group {sg_id} uses prefix list {prefix_list.get('PrefixListId')}")
                            
        except ClientError as e:
            logger.error(f"EC2 SG scan failed: {e}")
            
        return findings
    
   
    @retry_with_backoff()
    def scan_rds(self) -> List[Finding]:
        findings = []
        rds = AWSClientManager.get_client("rds", self.session)
        try:
            for db in rds.describe_db_instances().get("DBInstances", []):
                db_id = db["DBInstanceIdentifier"]
               
                if db.get("PubliclyAccessible"):
                    findings.append(self._make_finding(
                        id=f"rds-public-{db_id}",
                        title="RDS Publicly Accessible",
                        description=f"Database {db_id} is publicly accessible.",
                        severity=Severity.CRITICAL,
                        resource_type="RDS Instance",
                        resource_id=db_id,
                        remediation=f"aws rds modify-db-instance --db-instance-identifier {db_id} --no-publicly-accessible",
                        risk_score=92,
                        metadata={"db_id": db_id}
                    ))
               
                if not db.get("StorageEncrypted"):
                    findings.append(self._make_finding(
                        id=f"rds-unencrypted-{db_id}",
                        title="RDS Not Encrypted",
                        description=f"Database {db_id} has no storage encryption",
                        severity=Severity.HIGH,
                        resource_type="RDS Instance",
                        resource_id=db_id,
                        remediation=f"""Enable encryption requires snapshot/restore:
1. Create snapshot: aws rds create-db-snapshot --db-instance-identifier {db_id} --db-snapshot-identifier {db_id}-encrypted-snapshot
2. Restore encrypted: aws rds restore-db-instance-from-db-snapshot --db-instance-identifier {db_id}-encrypted --db-snapshot-identifier {db_id}-encrypted-snapshot --storage-encrypted
3. Update applications to use new instance
4. Delete old instance after testing""",
                        risk_score=85,
                        metadata={"db_id": db_id}
                    ))
                
                if not db.get("MultiAZ"):
                    findings.append(self._make_finding(
                        id=f"rds-multiaz-{db_id}",
                        title="RDS Not Multi-AZ",
                        description=f"Database {db_id} is not configured for Multi-AZ.",
                        severity=Severity.MEDIUM,
                        resource_type="RDS Instance",
                        resource_id=db_id,
                        remediation=f"aws rds modify-db-instance --db-instance-identifier {db_id} --multi-az",
                        risk_score=55,
                        metadata={"db_id": db_id}
                    ))
        except ClientError as e:
            logger.error(f"RDS scan failed: {e}")
        return findings
    
    
    def scan_cloudtrail(self) -> List[Finding]:
        findings = []
        ct = self.session.client("cloudtrail")
        try:
            trails = ct.describe_trails().get("trailList", [])
            if not trails:
                findings.append(self._make_finding(
                    id="cloudtrail-none",
                    title="CloudTrail Not Enabled",
                    description="No CloudTrail trails found.",
                    severity=Severity.CRITICAL,
                    resource_type="CloudTrail",
                    resource_id="account",
                    remediation="Enable CloudTrail: aws cloudtrail create-trail --name management-events --s3-bucket-name YOUR_BUCKET",
                    risk_score=88,
                    metadata={}
                ))
            else:
                for t in trails:
                    name = t["Name"]
                    if not t.get("LogFileValidationEnabled"):
                        findings.append(self._make_finding(
                            id=f"cloudtrail-validation-{name}",
                            title="CloudTrail Log Validation Disabled",
                            description=f"Trail {name} has log file validation disabled.",
                            severity=Severity.MEDIUM,
                            resource_type="CloudTrail",
                            resource_id=name,
                            remediation=f"aws cloudtrail update-trail --name {name} --enable-log-file-validation",
                            risk_score=50,
                            metadata={"trail": name}
                        ))
        except ClientError as e:
            logger.error(f"CloudTrail scan failed: {e}")
        return findings
    
    
    def scan_ebs_volumes(self) -> List[Finding]:
        findings = []
        ec2 = self.session.client("ec2")
        try:
            volumes = ec2.describe_volumes().get("Volumes", [])
            for vol in volumes:
                vol_id = vol["VolumeId"]
                state = vol.get("State", "unknown")
                if not vol.get("Encrypted", False):
                    severity = Severity.HIGH if state == "in-use" else Severity.MEDIUM
                    risk_score = 80 if state == "in-use" else 60
                    findings.append(self._make_finding(
                        id=f"ebs-unencrypted-{vol_id}",
                        title="EBS Volume Not Encrypted",
                        description=f"Volume {vol_id} ({state}) is not encrypted at rest.",
                        severity=severity,
                        resource_type="EBS Volume",
                        resource_id=vol_id,
                        remediation=f"Create encrypted snapshot: aws ec2 create-snapshot --volume-id {vol_id} --encrypted",
                        risk_score=risk_score,
                        metadata={"volume_id": vol_id, "state": state, "size": vol.get("Size", 0)}
                    ))
        except ClientError as e:
            logger.error(f"EBS scan failed: {e}")
        return findings

    @retry_with_backoff()
    def scan_kms_keys(self) -> List[Finding]:
        findings = []
        kms = AWSClientManager.get_client("kms", self.session)
        
        try:
            keys = kms.list_keys().get("Keys", [])
            if self.verbose:
                logger.info(f"Scanning {len(keys)} KMS keys...")
                
            for key in keys:
                key_id = key["KeyId"]
                try:
                    key_metadata = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                    if key_metadata.get("KeyManager") == "AWS":
                        continue
                        
                   
                    rotation_enabled = kms.get_key_rotation_status(KeyId=key_id).get("KeyRotationEnabled", False)
                    if not rotation_enabled:
                        findings.append(self._make_finding(
                            id=f"kms-rotation-{key_id}",
                            title="KMS Key Rotation Disabled",
                            description=f"KMS key {key_id} does not have automatic rotation enabled",
                            severity=Severity.MEDIUM,
                            resource_type="KMS Key",
                            resource_id=key_id,
                            remediation=f"aws kms enable-key-rotation --key-id {key_id}",
                            risk_score=55,
                            metadata={"key_id": key_id, "alias": key_metadata.get("Description", "N/A")}
                        ))
                    
                    
                    try:
                        key_policy = kms.get_key_policy(KeyId=key_id, PolicyName="default")
                        policy_doc = json.loads(key_policy.get("Policy", "{}"))
                        
                        for statement in policy_doc.get("Statement", []):
                            if statement.get("Effect") == "Allow":
                                principal = statement.get("Principal", {})
                                action = statement.get("Action", [])
                                
                             
                                if isinstance(principal.get("AWS"), str) and principal["AWS"] == "*":
                                    
                                    if any(action_item in ["kms:*", "kms:Decrypt", "kms:Encrypt"] for action_item in action):
                                        findings.append(self._make_finding(
                                            id=f"kms-permissive-policy-{key_id}",
                                            title="KMS Key Has Overly Permissive Policy",
                                            description=f"KMS key {key_id} has a policy allowing public access to encryption/decryption operations",
                                            severity=Severity.HIGH,
                                            resource_type="KMS Key",
                                            resource_id=key_id,
                                            remediation=f"Review and restrict key policy: aws kms get-key-policy --key-id {key_id} --policy-name default",
                                            risk_score=75,
                                            metadata={"key_id": key_id, "permissive_action": action}
                                        ))
                                        break
                                        
                    except ClientError:
                        pass 
                        
                except ClientError:
                    continue
                    
        except ClientError as e:
            logger.error(f"KMS scan failed: {e}")
            
        return findings

    def scan_vpc_flow_logs(self) -> List[Finding]:
        findings = []
        ec2 = self.session.client("ec2")
        try:
            vpcs = ec2.describe_vpcs().get("Vpcs", [])
            for vpc in vpcs:
                vpc_id = vpc["VpcId"]
                flow_logs = ec2.describe_flow_logs(Filters=[{"Name": "resource-id", "Values": [vpc_id]}]).get("FlowLogs", [])
                if not flow_logs:
                    is_default = vpc.get("IsDefault", False)
                    severity = Severity.HIGH if not is_default else Severity.MEDIUM
                    risk_score = 70 if not is_default else 50
                    findings.append(self._make_finding(
                        id=f"vpc-no-flowlogs-{vpc_id}",
                        title="VPC Flow Logs Not Enabled",
                        description=f"VPC {vpc_id} does not have flow logs enabled.",
                        severity=severity,
                        resource_type="VPC",
                        resource_id=vpc_id,
                        remediation=f"aws ec2 create-flow-logs --resource-type VPC --resource-ids {vpc_id} --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name /aws/vpc/flowlogs",
                        risk_score=risk_score,
                        metadata={"vpc_id": vpc_id, "is_default": is_default}
                    ))
        except ClientError as e:
            logger.error(f"VPC flow logs scan failed: {e}")
        return findings

    def scan_secrets_manager(self) -> List[Finding]:
        findings = []
        sm = self.session.client("secretsmanager")
        
        try:
            secrets = Paginator.get_all_items(sm, "list_secrets", "SecretList")
            if self.verbose:
                logger.info(f"Scanning {len(secrets)} Secrets Manager secrets...")
                
            for secret in secrets:
                secret_name = secret["Name"]
                secret_arn = secret["ARN"]
                
                
                rotation_enabled = secret.get("RotationEnabled", False)
                if not rotation_enabled:
                    remediation = f"Enable rotation: aws secretsmanager update-secret --secret-id {secret_arn} --description 'Updated with rotation'"
                    remediation += " && aws secretsmanager rotate-secret --secret-id {secret_arn} --rotation-lambda-arn YOUR_LAMBDA_ARN"
                    
                    findings.append(self._make_finding(
                        id=f"secrets-rotation-{secret_name}",
                        title="Secrets Manager Rotation Disabled",
                        description=f"Secret '{secret_name}' does not have automatic rotation enabled",
                        severity=Severity.MEDIUM,
                        resource_type="Secrets Manager Secret",
                        resource_id=secret_name,
                        remediation=remediation,
                        risk_score=60,
                        metadata={"secret_name": secret_name, "rotation_enabled": False}
                    ))
                else:
               
                    try:
                        secret_details = sm.describe_secret(SecretId=secret_arn)
                        rotation_config = secret_details.get("RotationRules", {})
                        
                        if not rotation_config.get("AutomaticallyAfterDays"):
                            findings.append(self._make_finding(
                                id=f"secrets-rotation-config-{secret_name}",
                                title="Secrets Manager Rotation Not Properly Configured",
                                description=f"Secret '{secret_name}' has rotation enabled but no rotation schedule configured",
                                severity=Severity.LOW,
                                resource_type="Secrets Manager Secret",
                                resource_id=secret_name,
                                remediation=f"Configure rotation schedule: aws secretsmanager update-secret --secret-id {secret_arn} --rotation-rules AutomaticallyAfterDays=30",
                                risk_score=30,
                                metadata={"secret_name": secret_name, "rotation_enabled": True, "schedule_missing": True}
                            ))
                            
                    except ClientError:
                        pass
                
              
                last_accessed = secret.get("LastAccessedDate")
                if last_accessed:
                    days_unused = (datetime.now(timezone.utc) - last_accessed).days
                    if days_unused > 90:
                        findings.append(self._make_finding(
                            id=f"secrets-unused-{secret_name}",
                            title="Unused Secret Detected",
                            description=f"Secret '{secret_name}' hasn't been accessed in {days_unused} days",
                            severity=Severity.LOW,
                            resource_type="Secrets Manager Secret",
                            resource_id=secret_name,
                            remediation=f"Review and delete if no longer needed: aws secretsmanager delete-secret --secret-id {secret_arn}",
                            risk_score=30,
                            metadata={"secret_name": secret_name, "days_unused": days_unused}
                        ))
                
                
                try:
                    secret_details = sm.describe_secret(SecretId=secret_arn)
                    replication_status = secret_details.get("ReplicationStatus", [])
                    
                    tags = secret_details.get("Tags", [])
                    tag_dict = {tag["Key"]: tag["Value"] for tag in tags}
                    
                    if tag_dict.get("MultiRegion", "false").lower() == "true" and not replication_status:
                        findings.append(self._make_finding(
                            id=f"secrets-replication-{secret_name}",
                            title="Secret Not Replicated Despite Tag",
                            description=f"Secret '{secret_name}' is tagged for multi-region but not replicated",
                            severity=Severity.MEDIUM,
                            resource_type="Secrets Manager Secret",
                            resource_id=secret_name,
                            remediation=f"Enable replication: aws secretsmanager replicate-secret-to-regions --secret-id {secret_arn} --add-replica-regions Region=us-west-2",
                            risk_score=50,
                            metadata={"secret_name": secret_name, "tagged_multi_region": True}
                        ))
                        
                except ClientError:
                    pass  
        
        except ClientError as e:
            logger.error(f"Secrets Manager scan failed: {e}")
        
        return findings
    
    def scan_lambda_functions(self) -> List[Finding]:
        findings = []
        lambda_client = self.session.client("lambda")
        
        
        deprecated_runtimes = {
            "python3.6": "2022-07-18",
            "python3.7": "2023-11-27", 
            "nodejs12.x": "2023-03-31",
            "nodejs10.x": "2021-07-30",
            "nodejs8.10": "2020-01-06",
            "dotnetcore2.1": "2022-01-05",
            "dotnetcore3.1": "2023-05-15",
            "ruby2.5": "2021-03-31",
            "ruby2.7": "2023-12-07"
        }
        
        try:
            functions = Paginator.get_all_items(lambda_client, "list_functions", "Functions")
            if self.verbose:
                logger.info(f"Scanning {len(functions)} Lambda functions...")
            
            for func in functions:
                func_name = func["FunctionName"]
                runtime = func.get("Runtime", "")
                
                
                if runtime in deprecated_runtimes:
                    findings.append(self._make_finding(
                        id=f"lambda-deprecated-runtime-{func_name}",
                        title="Lambda Using Deprecated Runtime",
                        description=f"Function '{func_name}' uses deprecated runtime '{runtime}' (EOL: {deprecated_runtimes[runtime]})",
                        severity=Severity.HIGH,
                        resource_type="Lambda Function",
                        resource_id=func_name,
                        remediation=f"Update runtime: aws lambda update-function-configuration --function-name {func_name} --runtime python3.11",
                        risk_score=75,
                        metadata={"function": func_name, "runtime": runtime, "eol_date": deprecated_runtimes[runtime]}
                    ))
                
              
                elif runtime and any(runtime.startswith(prefix) for prefix in ["python2", "nodejs6", "nodejs4", "java8"]):
                    findings.append(self._make_finding(
                        id=f"lambda-very-old-runtime-{func_name}",
                        title="Lambda Using Very Old Runtime",
                        description=f"Function '{func_name}' uses very old runtime '{runtime}' which may have security vulnerabilities",
                        severity=Severity.HIGH,
                        resource_type="Lambda Function",
                        resource_id=func_name,
                        remediation=f"Update runtime: aws lambda update-function-configuration --function-name {func_name} --runtime python3.11",
                        risk_score=70,
                        metadata={"function": func_name, "runtime": runtime}
                    ))
                
               
                try:
                    url_config = lambda_client.get_function_url_config(FunctionName=func_name)
                    auth_type = url_config.get("AuthType", "")
                    if auth_type == "NONE":
                        findings.append(self._make_finding(
                            id=f"lambda-public-url-{func_name}",
                            title="Lambda Function Has Public URL",
                            description=f"Function '{func_name}' has a publicly accessible URL without authentication",
                            severity=Severity.CRITICAL,
                            resource_type="Lambda Function",
                            resource_id=func_name,
                            remediation=f"Add authentication: aws lambda update-function-url-config --function-name {func_name} --auth-type AWS_IAM",
                            risk_score=90,
                            metadata={"function": func_name, "url": url_config.get("FunctionUrl", "")}
                        ))
                except lambda_client.exceptions.ResourceNotFoundException:
                    pass
                except ClientError:
                    pass
                    
                
                try:
                    policy = lambda_client.get_policy(FunctionName=func_name)
                    policy_doc = json.loads(policy.get("Policy", "{}"))
                    
                    for statement in policy_doc.get("Statement", []):
                        if statement.get("Effect") == "Allow":
                            principal = statement.get("Principal", {})
                            
                            
                            permissive_principals = []
                            
                            
                            if isinstance(principal.get("AWS"), str) and principal["AWS"] == "*":
                                permissive_principals.append("AWS:*")
                            elif isinstance(principal.get("AWS"), list) and "*" in principal["AWS"]:
                                permissive_principals.append("AWS:*")
                            
                            
                            if isinstance(principal.get("Service"), str) and principal["Service"] == "*":
                                permissive_principals.append("Service:*")
                            elif isinstance(principal.get("Service"), list) and "*" in principal["Service"]:
                                permissive_principals.append("Service:*")
                            
                            
                            if principal.get("Federated") == "*":
                                permissive_principals.append("Federated:*")
                            
                            if permissive_principals:
                                findings.append(self._make_finding(
                                    id=f"lambda-public-policy-{func_name}",
                                    title="Lambda Function Has Overly Permissive Policy",
                                    description=f"Function '{func_name}' has a resource policy with permissive principals: {', '.join(permissive_principals)}",
                                    severity=Severity.CRITICAL,
                                    resource_type="Lambda Function",
                                    resource_id=func_name,
                                    remediation=f"Review and restrict policy: aws lambda get-policy --function-name {func_name}",
                                    risk_score=85,
                                    metadata={"function": func_name, "permissive_principals": permissive_principals}
                                ))
                                break
                                
                except lambda_client.exceptions.ResourceNotFoundException:
                    pass
                except ClientError:
                    pass
        
        except ClientError as e:
            logger.error(f"Lambda scan failed: {e}")
        
        return findings


    def run_all(self) -> List[Finding]:
        """Execute all security checks in parallel and return findings"""
        findings = []
        all_checks = [
            ("s3", "S3 Buckets", self.scan_s3_buckets),
            ("iam", "IAM Policies", self.scan_iam),
            ("ec2", "EC2 Security Groups", self.scan_ec2_sgs),
            ("rds", "RDS Instances", self.scan_rds),
            ("cloudtrail", "CloudTrail", self.scan_cloudtrail),
            ("ebs", "EBS Volumes", self.scan_ebs_volumes),
            ("kms", "KMS Keys", self.scan_kms_keys),
            ("vpc", "VPC Flow Logs", self.scan_vpc_flow_logs),
            ("secrets", "Secrets Manager", self.scan_secrets_manager),
            ("lambda", "Lambda Functions", self.scan_lambda_functions)
        ]
        
        
        checks = [(name, check_name, check_func) for service_id, check_name, check_func in all_checks 
                 if service_id not in self.skip_services]
        
        if self.skip_services:
            logger.info(f"Skipping services: {', '.join(self.skip_services)}")
        
        logger.info(f"Starting parallel scan with {self.max_workers} workers...")
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
           
            future_to_check = {
                executor.submit(check_func): check_name 
                for check_name, check_func in checks
            }
            
       
            for future in as_completed(future_to_check):
                check_name = future_to_check[future]
                try:
                    check_findings = future.result()
                    findings.extend(check_findings)
                    
                    if self.verbose:
                        logger.info(f"✅ {check_name}: {len(check_findings)} findings")
                    else:
                        logger.info(f"✅ {check_name}: {len(check_findings)} issues found")
                        
                except Exception as e:
                    logger.error(f"❌ {check_name} failed: {e}")
                    continue
        
        elapsed_time = time.time() - start_time
        logger.info(f"Scan complete: {len(findings)} total findings across {len(checks)} services in {elapsed_time:.2f}s")
        
        return findings


class SecurityScoreCalculator:
    @staticmethod
    def calculate(findings: List[Finding]) -> Dict[str, Any]:
        counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
        for f in findings:
            counts[f.severity.value] += 1
        deductions = counts["CRITICAL"]*15 + counts["HIGH"]*10 + counts["MEDIUM"]*5 + counts["LOW"]*2
        score = max(0,100-deductions)
        grade = ("A" if score>=90 else "B" if score>=80 else "C" if score>=70 else "D" if score>=60 else "F")
        return {"score":score,"grade":grade,"counts":counts,"total":len(findings)}

class ReportGenerator:
    @staticmethod
    def json_report(findings: List[Finding], score: Dict[str, Any], stats: Dict[str, Any] = None) -> str:
        report = {
            "timestamp": utcnow_iso(),
            "score": score,
            "findings": [f.to_dict() for f in findings],
            "metadata": {
                "scanner_version": "2.0.0",
                "total_findings": len(findings),
                "severity_breakdown": score.get("counts", {}),
                "scan_duration": stats.get("scan_duration", 0) if stats else 0
            }
        }
        
        if stats:
            report["statistics"] = stats
            
        return json.dumps(report, indent=2)
    
    @staticmethod
    def html_report(findings: List[Finding], score: Dict[str, Any]) -> str:
        colors = {"CRITICAL":"#ff0000","HIGH":"#ff8800","MEDIUM":"#ffcc00","LOW":"#4CAF50"}
        html = f"<html><head><meta charset='UTF-8'><title>CloudGuard Report</title></head><body>"
        html += f"<h1>CloudGuard Enhanced Report</h1><p>Score: {score['score']} ({score['grade']})</p>"
        for f in sorted(findings, key=lambda x: x.risk_score, reverse=True):
            color = colors.get(f.severity.value,"#777")
            html += f"<div style='border:1px solid #ddd;padding:10px;margin:10px 0;'>"
            html += f"<h3>{f.title} <span style='color:{color}'>{f.severity.value}</span></h3>"
            html += f"<p>{f.description}</p><p>Resource: {f.resource_type} - {f.resource_id}</p>"
            html += f"<p>Remediation: {f.remediation}</p><p>Risk Score: {f.risk_score}</p></div>"
        html += "</body></html>"
        return html


class StatisticsGenerator:
    @staticmethod
    def generate_stats(findings: List[Finding]) -> Dict[str, Any]:
        if not findings: return {}
        by_resource = {}
        for f in findings:
            rt = f.resource_type
            by_resource[rt] = by_resource.get(rt, 0) + 1
        top_risky = sorted(findings, key=lambda x: x.risk_score, reverse=True)[:5]
        avg_risk = sum(f.risk_score for f in findings)/len(findings)
        return {
            "total_findings": len(findings),
            "by_resource_type": by_resource,
            "top_5_risky":[{"title":f.title,"resource":f.resource_id,"score":f.risk_score} for f in top_risky],
            "average_risk_score": round(avg_risk,2)
        }


def main():
    
    parser = argparse.ArgumentParser(
        description="CloudGuard Enhanced - AWS Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cg.py                           # Basic scan with defaults
  python cg.py --profile prod --region us-west-2  # Custom profile and region
  python cg.py --json custom.json --html custom.html  # Custom output files
        """
    )
    
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--region", default="us-east-1", help="AWS region to scan")
    parser.add_argument("--json", help="JSON output file path (use '-' for stdout)")
    parser.add_argument("--html", help="HTML output file path (use '-' for stdout)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--workers", type=int, default=8, help="Number of parallel workers (default: 8)")
    parser.add_argument("--skip-services", nargs="+", choices=["s3", "iam", "ec2", "rds", "cloudtrail", "ebs", "kms", "vpc", "secrets", "lambda"], help="Skip specific services")
    parser.add_argument("--fail-on-critical", action="store_true", help="Exit with error code if critical findings found")
    parser.add_argument("--version", action="version", version="CloudGuard Enhanced 2.0.0")
    
    args = parser.parse_args()
    
   
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        print("🛡️  CloudGuard Enhanced - AWS Security Scanner v2.0.0")
        print("=" * 60)
        
        
        scanner = AWSScanner(profile=args.profile, region=args.region, 
                           max_workers=args.workers, verbose=args.verbose,
                           skip_services=args.skip_services)
    
    
        print(f"🔍 Scanning AWS account: {scanner.account_id}")
        print(f"📍 Region: {args.region}")
        print(f"👤 Profile: {args.profile or 'default'}")
        print(f"⚡ Workers: {args.workers}")
        print("-" * 60)
        
        scan_start = time.time()
        findings = scanner.run_all()
        scan_duration = time.time() - scan_start
        
        score = SecurityScoreCalculator.calculate(findings)
        stats = StatisticsGenerator.generate_stats(findings)
        stats["scan_duration"] = round(scan_duration, 2)
    
       
        print("\n📄 Generating reports...")
        
        
        if args.json:
            json_content = ReportGenerator.json_report(findings, score, stats)
            if args.json == "-":
                print("\n" + "="*60)
                print("JSON REPORT")
                print("="*60)
                print(json_content)
            else:
                with open(args.json, "w") as f:
                    f.write(json_content)
                print(f"✅ JSON report saved: {args.json}")
        
        # HTML report
        if args.html:
            html_content = ReportGenerator.html_report(findings, score)
            if args.html == "-":
                print("\n" + "="*60)
                print("HTML REPORT")
                print("="*60)
                print(html_content)
            else:
                with open(args.html, "w") as f:
                    f.write(html_content)
                print(f"✅ HTML report saved: {args.html}")
        
        
        if not args.json and not args.html:
            with open("cloudguard_report.json", "w") as f:
                f.write(ReportGenerator.json_report(findings, score, stats))
            with open("cloudguard_report.html", "w") as f:
                f.write(ReportGenerator.html_report(findings, score))
            print("✅ Default reports saved: cloudguard_report.json, cloudguard_report.html")

        
        print("\n" + "=" * 60)
        print("📊 SECURITY SCAN RESULTS")
        print("=" * 60)
        print(f"🎯 Security Score: {score['score']}/100 (Grade: {score['grade']})")
        print(f"🔍 Total Findings: {score['total']}")
        print(f"   🚨 Critical: {score['counts']['CRITICAL']}")
        print(f"   ⚠️  High: {score['counts']['HIGH']}")
        print(f"   📊 Medium: {score['counts']['MEDIUM']}")
        print(f"   ℹ️  Low: {score['counts']['LOW']}")
        
        if stats:
            print(f"\n⏱️  Scan Duration: {stats['scan_duration']}s")
            print(f"📈 Average Risk Score: {stats.get('average_risk_score', 0)}/100")
            
            if stats.get('top_5_risky'):
                print("\n🔥 Top 5 Riskiest Resources:")
                for i, item in enumerate(stats['top_5_risky'], 1):
                    print(f"   {i}. {item['title']} ({item['resource']}) - {item['score']}/100")
        
        print(f"\n📄 Reports Generated:")
        if args.json:
            print(f"   📋 JSON: {args.json if args.json != '-' else 'stdout'}")
        if args.html:
            print(f"   🌐 HTML: {args.html if args.html != '-' else 'stdout'}")
        if not args.json and not args.html:
            print(f"   📋 JSON: cloudguard_report.json")
            print(f"   🌐 HTML: cloudguard_report.html")
        
        
        if args.fail_on_critical and score['counts']['CRITICAL'] > 0:
            print(f"\n⚠️  WARNING: {score['counts']['CRITICAL']} critical findings detected!")
            sys.exit(1)
        
        
        if score['counts']['CRITICAL'] > 0:
            print(f"\n⚠️  Found {score['counts']['CRITICAL']} critical issues - review reports for details")
        else:
            print("\n✅ No critical issues found!")
        
        print("\n🎉 Scan Complete!\n")

    except KeyboardInterrupt:
        print("\n❌ Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        print(f"\n❌ Scan failed: {e}")
        sys.exit(1)

if __name__=="__main__":
    main()
          
