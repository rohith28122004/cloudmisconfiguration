# AWS Setup Guide for Cloud Security Scanner

This guide explains how to configure AWS credentials to scan your real AWS cloud infrastructure.

## Prerequisites

1. **Install boto3**: The AWS SDK for Python
   ```bash
   pip install boto3
   ```

2. **AWS Account**: You need an AWS account with appropriate permissions

## Authentication Methods

### Method 1: AWS Credentials File (Recommended)

1. Create the AWS credentials directory:
   ```bash
   # Windows
   mkdir %USERPROFILE%\.aws
   
   # Linux/Mac
   mkdir ~/.aws
   ```

2. Create/edit the credentials file:
   ```bash
   # Windows
   notepad %USERPROFILE%\.aws\credentials
   
   # Linux/Mac
   nano ~/.aws/credentials
   ```

3. Add your AWS credentials:
   ```ini
   [default]
   aws_access_key_id = YOUR_ACCESS_KEY_ID
   aws_secret_access_key = YOUR_SECRET_ACCESS_KEY
   
   [scanner-profile]
   aws_access_key_id = YOUR_ACCESS_KEY_ID
   aws_secret_access_key = YOUR_SECRET_ACCESS_KEY
   ```

4. Create/edit the config file:
   ```bash
   # Windows
   notepad %USERPROFILE%\.aws\config
   
   # Linux/Mac
   nano ~/.aws/config
   ```

5. Add your default region:
   ```ini
   [default]
   region = us-east-1
   
   [profile scanner-profile]
   region = ap-south-1
   ```

### Method 2: Environment Variables

Set environment variables in your terminal:

**Windows (PowerShell):**
```powershell
$env:AWS_ACCESS_KEY_ID="YOUR_ACCESS_KEY_ID"
$env:AWS_SECRET_ACCESS_KEY="YOUR_SECRET_ACCESS_KEY"
$env:AWS_DEFAULT_REGION="us-east-1"
```

**Linux/Mac:**
```bash
export AWS_ACCESS_KEY_ID="YOUR_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="YOUR_SECRET_ACCESS_KEY"
export AWS_DEFAULT_REGION="us-east-1"
```

### Method 3: IAM Role (For EC2 Instances)

If running on an EC2 instance, attach an IAM role with appropriate permissions. No credentials needed!

## Required IAM Permissions

Create an IAM user or role with these permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketAcl",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "iam:ListMFADevices",
        "iam:ListAttachedUserPolicies",
        "rds:DescribeDBInstances",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## How to Get AWS Access Keys

1. Sign in to AWS Console: https://console.aws.amazon.com/
2. Go to **IAM** (Identity and Access Management)
3. Click **Users** in the left sidebar
4. Click **Add users** or select an existing user
5. For new users:
   - Enter username (e.g., "cloud-scanner")
   - Select **Access key - Programmatic access**
   - Click **Next: Permissions**
   - Attach the policy above (create a custom policy or use ReadOnlyAccess)
   - Click through to **Create user**
6. **IMPORTANT**: Download the CSV with your credentials or copy them immediately
   - You won't be able to see the secret key again!

## Using the Scanner with Real AWS

### Option 1: Modify app.py to use real AWS

Edit `app.py` line 23:
```python
# Change from:
cloud_connector = CloudConnector(demo_mode=True)

# To:
cloud_connector = CloudConnector(demo_mode=False, region='us-east-1')
```

### Option 2: Add a toggle in the UI (Future Enhancement)

You can add a button in the login page to choose between demo and real AWS mode.

## Testing the Connection

Run this test script to verify your credentials:

```python
import boto3

try:
    # Create STS client
    sts = boto3.client('sts')
    
    # Get account information
    identity = sts.get_caller_identity()
    
    print("✓ AWS Connection Successful!")
    print(f"  Account ID: {identity['Account']}")
    print(f"  User ARN: {identity['Arn']}")
    
except Exception as e:
    print(f"✗ AWS Connection Failed: {e}")
```

## Security Best Practices

1. **Never commit credentials to Git**
   - The `.gitignore` already excludes AWS credential files
   - Never hardcode keys in source code

2. **Use IAM roles when possible**
   - Preferred for EC2, Lambda, ECS, etc.
   - No credentials to manage!

3. **Rotate access keys regularly**
   - AWS recommends rotating every 90 days
   - The scanner will detect old keys!

4. **Use least privilege**
   - Only grant permissions needed for scanning
   - Consider using AWS managed policy: `SecurityAudit`

5. **Enable MFA**
   - Protect your AWS account with multi-factor authentication

## Troubleshooting

### "No credentials found"
- Check that credentials file exists at `~/.aws/credentials`
- Verify environment variables are set correctly
- Try running: `aws configure` (if AWS CLI is installed)

### "Access Denied" errors
- Verify your IAM user/role has the required permissions
- Check the IAM policy attached to your user

### "Region not found"
- Ensure you've set a valid AWS region
- Common regions: `us-east-1`, `us-west-2`, `ap-south-1`, `eu-west-1`

### Connection timeout
- Check your internet connection
- Verify firewall/proxy settings
- Try a different region

## Regions

Common AWS regions:
- `us-east-1` - US East (N. Virginia)
- `us-west-2` - US West (Oregon)
- `ap-south-1` - Asia Pacific (Mumbai) - **India**
- `eu-west-1` - Europe (Ireland)
- `ap-southeast-1` - Asia Pacific (Singapore)

## Cost Considerations

The scanner uses **read-only API calls** which are:
- ✓ Generally **FREE** or very low cost
- ✓ No resources are created or modified
- ✓ Safe to run multiple times

Typical cost: **$0.00 - $0.01** per scan

## Next Steps

1. Install boto3: `pip install boto3`
2. Configure your AWS credentials using one of the methods above
3. Test the connection with the test script
4. Modify `app.py` to set `demo_mode=False`
5. Run the scanner: `python app.py`
6. Access the scanner at: http://localhost:5000

## Support

For issues:
- Check AWS CloudTrail for API call errors
- Review IAM permissions
- Verify credentials are correctly configured
- Check the scanner console output for detailed error messages
