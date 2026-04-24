"""
Cloud Connector Module
Handles connection to cloud providers and fetching resource data.
Supports both demo mode and real AWS integration using boto3.
"""

import json
import os
from typing import Dict, List, Any
from datetime import datetime

# Try to import boto3, fallback to demo mode if not available
try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    print("⚠️  boto3 not installed. Only demo mode available.")
    print("   Install with: pip install boto3")

class CloudConnector:
    """Connects to cloud providers and fetches resource information."""
    
    def __init__(self, demo_mode: bool = True, aws_profile: str = None, region: str = 'us-east-1'):
        self.demo_mode = demo_mode
        self.provider = "AWS"
        self.resources = []
        self.aws_profile = aws_profile
        self.region = region
        self.session = None
        self.account_id = None
        
        # Force demo mode if boto3 not available
        if not BOTO3_AVAILABLE and not demo_mode:
            print("[WARNING] boto3 not available. Forcing demo mode.")
            self.demo_mode = True
        
    def connect(self, credentials: Dict = None) -> bool:
        """
        Connect to cloud provider.
        In demo mode, no real credentials are needed.
        In AWS mode, uses boto3 to connect with credentials.
        """
        if self.demo_mode:
            print("[INFO] Running in DEMO mode")
            return True
        
        if not BOTO3_AVAILABLE:
            print("[ERROR] boto3 not installed. Cannot connect to AWS.")
            return False
        
        try:
            # Create boto3 session
            if self.aws_profile:
                self.session = boto3.Session(profile_name=self.aws_profile, region_name=self.region)
                print(f"[INFO] Using AWS profile: {self.aws_profile}")
            elif credentials:
                self.session = boto3.Session(
                    aws_access_key_id=credentials.get('access_key_id'),
                    aws_secret_access_key=credentials.get('secret_access_key'),
                    region_name=credentials.get('region', self.region)
                )
                print("[INFO] Using provided AWS credentials")
            else:
                # Use default credentials (environment variables or ~/.aws/credentials)
                self.session = boto3.Session(region_name=self.region)
                print("[INFO] Using default AWS credentials")
            
            # Verify credentials by getting account ID
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            self.account_id = identity['Account']
            
            print(f"[SUCCESS] Connected to AWS Account: {self.account_id}")
            return True
            
        except NoCredentialsError:
            print("[ERROR] No AWS credentials found. Please configure credentials.")
            print("        Options:")
            print("        1. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables")
            print("        2. Configure ~/.aws/credentials file")
            print("        3. Use IAM role (if running on EC2)")
            return False
        except ClientError as e:
            print(f"[ERROR] AWS connection failed: {e}")
            return False
        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")
            return False
    
    def fetch_resources(self) -> List[Dict[str, Any]]:
        """
        Fetch all cloud resources.
        In demo mode, loads from demo_resources.json
        In AWS mode, fetches real resources using boto3
        """
        if self.demo_mode:
            return self._load_demo_resources()
        
        if not self.session:
            print("[ERROR] Not connected to AWS. Call connect() first.")
            return []
        
        print("[INFO] Fetching resources from AWS...")
        resources = []
        
        # Fetch S3 buckets
        resources.extend(self._fetch_s3_buckets())
        
        # Fetch EC2 instances
        resources.extend(self._fetch_ec2_instances())
        
        # Fetch IAM users
        resources.extend(self._fetch_iam_users())
        
        # Fetch RDS instances
        resources.extend(self._fetch_rds_instances())
        
        self.resources = resources
        print(f"[SUCCESS] Fetched {len(resources)} resources from AWS")
        return resources
    
    def _fetch_s3_buckets(self) -> List[Dict]:
        """Fetch S3 bucket information."""
        resources = []
        try:
            s3 = self.session.client('s3')
            buckets = s3.list_buckets()
            
            for bucket in buckets.get('Buckets', []):
                bucket_name = bucket['Name']
                
                # Get bucket location
                try:
                    location = s3.get_bucket_location(Bucket=bucket_name)
                    region = location.get('LocationConstraint') or 'us-east-1'
                except:
                    region = 'unknown'
                
                # Check public access
                try:
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    public_access = any(
                        grant['Grantee'].get('Type') == 'Group' and 
                        'AllUsers' in grant['Grantee'].get('URI', '')
                        for grant in acl.get('Grants', [])
                    )
                except:
                    public_access = False
                
                # Check encryption
                try:
                    encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                    has_encryption = True
                except:
                    has_encryption = False
                
                # Check versioning
                try:
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                    has_versioning = versioning.get('Status') == 'Enabled'
                except:
                    has_versioning = False
                
                # Check logging
                try:
                    logging = s3.get_bucket_logging(Bucket=bucket_name)
                    has_logging = 'LoggingEnabled' in logging
                except:
                    has_logging = False
                
                resources.append({
                    'id': f's3-{bucket_name}',
                    'type': 'S3_Bucket',
                    'name': bucket_name,
                    'region': region,
                    'created_date': bucket['CreationDate'].strftime('%Y-%m-%d'),
                    'properties': {
                        'public_access': public_access,
                        'encryption': has_encryption,
                        'versioning': has_versioning,
                        'logging': has_logging,
                        'data_classification': 'Internal',  # Default, should be tagged
                        'contains_financial_data': False,  # Default, should be tagged
                        'days_public': 0 if not public_access else 30  # Estimate
                    }
                })
            
            print(f"[INFO] Fetched {len(resources)} S3 buckets")
        except Exception as e:
            print(f"[WARNING] Failed to fetch S3 buckets: {e}")
        
        return resources
    
    def _fetch_ec2_instances(self) -> List[Dict]:
        """Fetch EC2 instance information."""
        resources = []
        try:
            ec2 = self.session.client('ec2')
            instances = ec2.describe_instances()
            
            for reservation in instances.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_id = instance['InstanceId']
                    
                    # Check if instance has public IP
                    has_public_ip = instance.get('PublicIpAddress') is not None
                    
                    # Check security groups for open ports
                    security_groups = instance.get('SecurityGroups', [])
                    open_ports = []
                    sg_open = False
                    
                    for sg in security_groups:
                        try:
                            sg_details = ec2.describe_security_groups(GroupIds=[sg['GroupId']])
                            for sg_detail in sg_details.get('SecurityGroups', []):
                                for rule in sg_detail.get('IpPermissions', []):
                                    if any(ip.get('CidrIp') == '0.0.0.0/0' for ip in rule.get('IpRanges', [])):
                                        sg_open = True
                                        if rule.get('FromPort'):
                                            open_ports.append(rule['FromPort'])
                        except:
                            pass
                    
                    # Check IMDSv2
                    metadata_options = instance.get('MetadataOptions', {})
                    imdsv2_enforced = metadata_options.get('HttpTokens') == 'required'
                    
                    # Check EBS encryption
                    ebs_encrypted = all(
                        bdm.get('Ebs', {}).get('Encrypted', False)
                        for bdm in instance.get('BlockDeviceMappings', [])
                    )
                    
                    # Check monitoring
                    monitoring = instance.get('Monitoring', {}).get('State') == 'enabled'
                    
                    resources.append({
                        'id': instance_id,
                        'type': 'EC2_Instance',
                        'name': instance_id,
                        'region': self.region,
                        'created_date': instance.get('LaunchTime', datetime.now()).strftime('%Y-%m-%d'),
                        'properties': {
                            'public_ip': has_public_ip,
                            'security_group_open': sg_open,
                            'imdsv2_enforced': imdsv2_enforced,
                            'ebs_encryption': ebs_encrypted,
                            'monitoring': monitoring,
                            'instance_type': instance.get('InstanceType', 'unknown'),
                            'open_ports': open_ports,
                            'state': instance.get('State', {}).get('Name', 'unknown')
                        }
                    })
            
            print(f"[INFO] Fetched {len(resources)} EC2 instances")
        except Exception as e:
            print(f"[WARNING] Failed to fetch EC2 instances: {e}")
        
        return resources
    
    def _fetch_iam_users(self) -> List[Dict]:
        """Fetch IAM user information."""
        resources = []
        try:
            iam = self.session.client('iam')
            users = iam.list_users()
            
            for user in users.get('Users', []):
                username = user['UserName']
                
                # Check for access keys
                try:
                    keys = iam.list_access_keys(UserName=username)
                    access_keys = keys.get('AccessKeyMetadata', [])
                    
                    # Calculate key age
                    key_age_days = 0
                    if access_keys:
                        oldest_key = min(access_keys, key=lambda k: k['CreateDate'])
                        key_age_days = (datetime.now(oldest_key['CreateDate'].tzinfo) - oldest_key['CreateDate']).days
                    
                    has_access_keys = len(access_keys) > 0
                except:
                    has_access_keys = False
                    key_age_days = 0
                
                # Check for MFA
                try:
                    mfa_devices = iam.list_mfa_devices(UserName=username)
                    has_mfa = len(mfa_devices.get('MFADevices', [])) > 0
                except:
                    has_mfa = False
                
                # Check for admin policies
                try:
                    policies = iam.list_attached_user_policies(UserName=username)
                    has_admin = any(
                        'Admin' in policy['PolicyName'] or policy['PolicyArn'].endswith('AdministratorAccess')
                        for policy in policies.get('AttachedPolicies', [])
                    )
                except:
                    has_admin = False
                
                resources.append({
                    'id': f'iam-{username}',
                    'type': 'IAM_User',
                    'name': username,
                    'region': 'global',
                    'created_date': user.get('CreateDate', datetime.now()).strftime('%Y-%m-%d'),
                    'properties': {
                        'has_access_keys': has_access_keys,
                        'access_key_age_days': key_age_days,
                        'mfa_enabled': has_mfa,
                        'admin_access': has_admin,
                        'password_enabled': user.get('PasswordLastUsed') is not None
                    }
                })
            
            print(f"[INFO] Fetched {len(resources)} IAM users")
        except Exception as e:
            print(f"[WARNING] Failed to fetch IAM users: {e}")
        
        return resources
    
    def _fetch_rds_instances(self) -> List[Dict]:
        """Fetch RDS instance information."""
        resources = []
        try:
            rds = self.session.client('rds')
            instances = rds.describe_db_instances()
            
            for instance in instances.get('DBInstances', []):
                db_id = instance['DBInstanceIdentifier']
                
                # Check public accessibility
                publicly_accessible = instance.get('PubliclyAccessible', False)
                
                # Check encryption
                encrypted = instance.get('StorageEncrypted', False)
                
                # Check backup retention
                backup_retention = instance.get('BackupRetentionPeriod', 0)
                
                # Check multi-AZ
                multi_az = instance.get('MultiAZ', False)
                
                resources.append({
                    'id': f'rds-{db_id}',
                    'type': 'RDS_Instance',
                    'name': db_id,
                    'region': self.region,
                    'created_date': instance.get('InstanceCreateTime', datetime.now()).strftime('%Y-%m-%d'),
                    'properties': {
                        'publicly_accessible': publicly_accessible,
                        'encryption': encrypted,
                        'backup_retention_days': backup_retention,
                        'multi_az': multi_az,
                        'engine': instance.get('Engine', 'unknown'),
                        'engine_version': instance.get('EngineVersion', 'unknown'),
                        'contains_financial_data': False,  # Should be tagged
                        'data_classification': 'Internal'  # Should be tagged
                    }
                })
            
            print(f"[INFO] Fetched {len(resources)} RDS instances")
        except Exception as e:
            print(f"[WARNING] Failed to fetch RDS instances: {e}")
        
        return resources
    
    def _load_demo_resources(self) -> List[Dict[str, Any]]:
        """Load demo resources from JSON file."""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        demo_file = os.path.join(base_dir, 'data', 'demo_resources.json')
        
        try:
            with open(demo_file, 'r') as f:
                data = json.load(f)
                self.resources = data.get('resources', [])
                print(f"[INFO] Loaded {len(self.resources)} demo resources")
                return self.resources
        except Exception as e:
            print(f"[ERROR] Error loading demo resources: {e}")
            return []
    
    def get_resource_by_id(self, resource_id: str) -> Dict:
        """Get a specific resource by ID."""
        for resource in self.resources:
            if resource.get('id') == resource_id:
                return resource
        return None
    
    def get_resources_by_type(self, resource_type: str) -> List[Dict]:
        """Get all resources of a specific type."""
        return [r for r in self.resources if r.get('type') == resource_type]
    
    def get_resource_summary(self) -> Dict[str, int]:
        """Get count of resources by type."""
        summary = {}
        for resource in self.resources:
            r_type = resource.get('type', 'Unknown')
            summary[r_type] = summary.get(r_type, 0) + 1
        return summary
    
    def get_cloud_info(self) -> Dict:
        """Get cloud account information."""
        if self.demo_mode:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            demo_file = os.path.join(base_dir, 'data', 'demo_resources.json')
            
            try:
                with open(demo_file, 'r') as f:
                    data = json.load(f)
                    return {
                        'provider': data.get('cloud_provider', 'AWS'),
                        'account_id': data.get('account_id', 'Demo Account'),
                        'scan_timestamp': data.get('scan_timestamp', ''),
                        'demo_mode': True
                    }
            except:
                return {'provider': 'AWS', 'account_id': 'Demo', 'demo_mode': True}
        
        return {
            'provider': self.provider,
            'account_id': self.account_id or 'Unknown',
            'scan_timestamp': datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ'),
            'demo_mode': False,
            'region': self.region
        }
