"""
AWS Cloud Configuration Exporter
Exports your real AWS cloud resources to JSON format for Cloud Security Scanner

Prerequisites:
1. Install boto3: pip install boto3
2. Configure AWS credentials: aws configure
   OR set environment variables:
   - AWS_ACCESS_KEY_ID
   - AWS_SECRET_ACCESS_KEY
   - AWS_DEFAULT_REGION

Usage:
    python export_aws_config.py
    
Output:
    my-aws-config.json (ready to upload to scanner)
"""

import boto3
import json
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError

def check_aws_credentials():
    """Verify AWS credentials are configured."""
    try:
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        print(f"✓ Connected to AWS Account: {identity['Account']}")
        print(f"✓ User ARN: {identity['Arn']}")
        return identity['Account']
    except NoCredentialsError:
        print("✗ ERROR: AWS credentials not found!")
        print("\nPlease configure AWS credentials:")
        print("  Option 1: Run 'aws configure'")
        print("  Option 2: Set environment variables AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
        return None
    except Exception as e:
        print(f"✗ ERROR: {e}")
        return None

def fetch_s3_buckets(region='ap-south-1'):
    """Fetch all S3 buckets and their security properties."""
    print("\n[1/6] Fetching S3 Buckets...")
    s3 = boto3.client('s3', region_name=region)
    resources = []
    
    try:
        buckets = s3.list_buckets()
        
        for bucket in buckets['Buckets']:
            bucket_name = bucket['Name']
            print(f"  - Analyzing bucket: {bucket_name}")
            
            # Check encryption
            has_encryption = False
            try:
                s3.get_bucket_encryption(Bucket=bucket_name)
                has_encryption = True
            except ClientError:
                pass
            
            # Check public access
            is_public = True
            try:
                public_block = s3.get_public_access_block(Bucket=bucket_name)
                config = public_block['PublicAccessBlockConfiguration']
                is_public = not (config.get('BlockPublicAcls', False) and 
                               config.get('BlockPublicPolicy', False))
            except ClientError:
                pass
            
            # Check versioning
            has_versioning = False
            try:
                versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                has_versioning = versioning.get('Status') == 'Enabled'
            except ClientError:
                pass
            
            # Check logging
            has_logging = False
            try:
                logging = s3.get_bucket_logging(Bucket=bucket_name)
                has_logging = 'LoggingEnabled' in logging
            except ClientError:
                pass
            
            resources.append({
                "id": f"s3-{bucket_name}",
                "type": "S3_Bucket",
                "name": bucket_name,
                "region": region,
                "created_date": bucket['CreationDate'].strftime('%Y-%m-%d'),
                "properties": {
                    "public_access": is_public,
                    "encryption": has_encryption,
                    "versioning": has_versioning,
                    "logging": has_logging,
                    "data_classification": "Internal",  # User should update this
                    "contains_financial_data": False,   # User should update this
                    "days_public": 0 if not is_public else 30  # Estimate
                }
            })
        
        print(f"  ✓ Found {len(resources)} S3 buckets")
    except Exception as e:
        print(f"  ✗ Error fetching S3 buckets: {e}")
    
    return resources

def fetch_ec2_instances(region='ap-south-1'):
    """Fetch all EC2 instances and their security properties."""
    print("\n[2/6] Fetching EC2 Instances...")
    ec2 = boto3.client('ec2', region_name=region)
    resources = []
    
    try:
        response = ec2.describe_instances()
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                print(f"  - Analyzing instance: {instance_id}")
                
                # Get instance name from tags
                instance_name = instance_id
                for tag in instance.get('Tags', []):
                    if tag['Key'] == 'Name':
                        instance_name = tag['Value']
                        break
                
                # Check if instance has public IP
                has_public_ip = instance.get('PublicIpAddress') is not None
                
                # Check security groups (simplified - checks if any SG allows 0.0.0.0/0)
                has_open_sg = False
                try:
                    for sg in instance.get('SecurityGroups', []):
                        sg_details = ec2.describe_security_groups(GroupIds=[sg['GroupId']])
                        for rule in sg_details['SecurityGroups'][0].get('IpPermissions', []):
                            for ip_range in rule.get('IpRanges', []):
                                if ip_range.get('CidrIp') == '0.0.0.0/0':
                                    has_open_sg = True
                                    break
                except:
                    pass
                
                # Check EBS encryption
                has_ebs_encryption = False
                for bdm in instance.get('BlockDeviceMappings', []):
                    if 'Ebs' in bdm:
                        has_ebs_encryption = bdm['Ebs'].get('Encrypted', False)
                        break
                
                # Check monitoring
                monitoring_enabled = instance.get('Monitoring', {}).get('State') == 'enabled'
                
                resources.append({
                    "id": instance_id,
                    "type": "EC2_Instance",
                    "name": instance_name,
                    "region": region,
                    "created_date": instance['LaunchTime'].strftime('%Y-%m-%d'),
                    "properties": {
                        "public_ip": has_public_ip,
                        "security_group_open": has_open_sg,
                        "imdsv2_enforced": False,  # Requires additional check
                        "ebs_encryption": has_ebs_encryption,
                        "monitoring": monitoring_enabled,
                        "instance_type": instance['InstanceType'],
                        "open_ports": [22, 80, 443] if has_open_sg else []
                    }
                })
        
        print(f"  ✓ Found {len(resources)} EC2 instances")
    except Exception as e:
        print(f"  ✗ Error fetching EC2 instances: {e}")
    
    return resources

def fetch_rds_databases(region='ap-south-1'):
    """Fetch all RDS databases and their security properties."""
    print("\n[3/6] Fetching RDS Databases...")
    rds = boto3.client('rds', region_name=region)
    resources = []
    
    try:
        response = rds.describe_db_instances()
        
        for db in response['DBInstances']:
            db_id = db['DBInstanceIdentifier']
            print(f"  - Analyzing database: {db_id}")
            
            resources.append({
                "id": f"rds-{db_id}",
                "type": "RDS_Database",
                "name": db_id,
                "region": region,
                "created_date": db['InstanceCreateTime'].strftime('%Y-%m-%d'),
                "properties": {
                    "publicly_accessible": db.get('PubliclyAccessible', False),
                    "encryption": db.get('StorageEncrypted', False),
                    "backup_enabled": db.get('BackupRetentionPeriod', 0) > 0,
                    "multi_az": db.get('MultiAZ', False),
                    "auto_minor_version_upgrade": db.get('AutoMinorVersionUpgrade', False),
                    "deletion_protection": db.get('DeletionProtection', False),
                    "engine": db.get('Engine', 'unknown'),
                    "engine_version": db.get('EngineVersion', 'unknown')
                }
            })
        
        print(f"  ✓ Found {len(resources)} RDS databases")
    except Exception as e:
        print(f"  ✗ Error fetching RDS databases: {e}")
    
    return resources

def fetch_iam_users():
    """Fetch all IAM users and their security properties."""
    print("\n[4/6] Fetching IAM Users...")
    iam = boto3.client('iam')
    resources = []
    
    try:
        response = iam.list_users()
        
        for user in response['Users']:
            username = user['UserName']
            print(f"  - Analyzing user: {username}")
            
            # Check MFA
            mfa_devices = iam.list_mfa_devices(UserName=username)
            has_mfa = len(mfa_devices['MFADevices']) > 0
            
            # Check for admin policies
            has_admin = False
            try:
                attached_policies = iam.list_attached_user_policies(UserName=username)
                for policy in attached_policies['AttachedPolicies']:
                    if 'Admin' in policy['PolicyName']:
                        has_admin = True
                        break
            except:
                pass
            
            # Check access keys
            access_keys = iam.list_access_keys(UserName=username)
            keys_rotated = True
            for key in access_keys['AccessKeyMetadata']:
                key_age = (datetime.now(key['CreateDate'].tzinfo) - key['CreateDate']).days
                if key_age > 90:
                    keys_rotated = False
            
            # Calculate user age
            user_age = (datetime.now(user['CreateDate'].tzinfo) - user['CreateDate']).days
            
            resources.append({
                "id": f"iam-{username}",
                "type": "IAM_User",
                "name": username,
                "region": "global",
                "created_date": user['CreateDate'].strftime('%Y-%m-%d'),
                "properties": {
                    "has_admin_policy": has_admin,
                    "mfa_enabled": has_mfa,
                    "access_keys_rotated": keys_rotated,
                    "unused_days": 0,  # Requires CloudTrail analysis
                    "password_age_days": user_age,
                    "console_access": True  # Assume true if user exists
                }
            })
        
        print(f"  ✓ Found {len(resources)} IAM users")
    except Exception as e:
        print(f"  ✗ Error fetching IAM users: {e}")
    
    return resources

def fetch_lambda_functions(region='ap-south-1'):
    """Fetch all Lambda functions and their security properties."""
    print("\n[5/6] Fetching Lambda Functions...")
    lambda_client = boto3.client('lambda', region_name=region)
    resources = []
    
    try:
        response = lambda_client.list_functions()
        
        for func in response['Functions']:
            func_name = func['FunctionName']
            print(f"  - Analyzing function: {func_name}")
            
            # Check VPC configuration
            has_vpc = 'VpcConfig' in func and func['VpcConfig'].get('VpcId')
            
            # Check environment variable encryption
            env_encrypted = func.get('KMSKeyArn') is not None
            
            # Check tracing
            tracing_enabled = func.get('TracingConfig', {}).get('Mode') == 'Active'
            
            resources.append({
                "id": f"lambda-{func_name}",
                "type": "Lambda_Function",
                "name": func_name,
                "region": region,
                "created_date": func.get('LastModified', '2024-01-01')[:10],
                "properties": {
                    "public_access": False,  # Requires policy analysis
                    "vpc_enabled": has_vpc,
                    "environment_vars_encrypted": env_encrypted,
                    "tracing_enabled": tracing_enabled,
                    "reserved_concurrency": func.get('ReservedConcurrentExecutions', 0),
                    "runtime": func.get('Runtime', 'unknown')
                }
            })
        
        print(f"  ✓ Found {len(resources)} Lambda functions")
    except Exception as e:
        print(f"  ✗ Error fetching Lambda functions: {e}")
    
    return resources

def fetch_cloudtrail(region='ap-south-1'):
    """Fetch CloudTrail configuration."""
    print("\n[6/6] Fetching CloudTrail Configuration...")
    cloudtrail = boto3.client('cloudtrail', region_name=region)
    resources = []
    
    try:
        response = cloudtrail.describe_trails()
        
        for trail in response['trailList']:
            trail_name = trail['Name']
            print(f"  - Analyzing trail: {trail_name}")
            
            # Get trail status
            status = cloudtrail.get_trail_status(Name=trail_name)
            
            resources.append({
                "id": f"cloudtrail-{trail_name}",
                "type": "CloudTrail",
                "name": trail_name,
                "region": region,
                "created_date": "2024-01-01",  # Not available in API
                "properties": {
                    "enabled": status.get('IsLogging', False),
                    "log_file_validation": trail.get('LogFileValidationEnabled', False),
                    "multi_region": trail.get('IsMultiRegionTrail', False),
                    "s3_bucket_logging": True,  # Assume true if trail exists
                    "kms_encryption": trail.get('KmsKeyId') is not None
                }
            })
        
        print(f"  ✓ Found {len(resources)} CloudTrail configurations")
    except Exception as e:
        print(f"  ✗ Error fetching CloudTrail: {e}")
    
    return resources

def export_configuration(region='ap-south-1', output_file='my-aws-config.json'):
    """Main function to export AWS configuration."""
    print("=" * 60)
    print("AWS Cloud Configuration Exporter")
    print("=" * 60)
    
    # Check credentials
    account_id = check_aws_credentials()
    if not account_id:
        return
    
    print(f"\nExporting resources from region: {region}")
    print("This may take a few minutes...\n")
    
    # Fetch all resources
    all_resources = []
    all_resources.extend(fetch_s3_buckets(region))
    all_resources.extend(fetch_ec2_instances(region))
    all_resources.extend(fetch_rds_databases(region))
    all_resources.extend(fetch_iam_users())
    all_resources.extend(fetch_lambda_functions(region))
    all_resources.extend(fetch_cloudtrail(region))
    
    # Create output JSON
    output = {
        "cloud_provider": "AWS",
        "account_id": account_id,
        "scan_timestamp": datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ'),
        "resources": all_resources
    }
    
    # Save to file
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    print("\n" + "=" * 60)
    print(f"✓ Export Complete!")
    print(f"✓ Total resources exported: {len(all_resources)}")
    print(f"✓ Output file: {output_file}")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Review the generated JSON file")
    print("2. Update 'data_classification' fields for S3 buckets")
    print("3. Upload to Cloud Security Scanner at http://localhost:5000")
    print("4. Click 'Upload Configuration' and select this file")
    print("5. Start the security scan!")

if __name__ == "__main__":
    # You can change the region here
    REGION = 'ap-south-1'  # Change to your AWS region
    OUTPUT_FILE = 'my-aws-config.json'
    
    export_configuration(region=REGION, output_file=OUTPUT_FILE)
