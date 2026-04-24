# 🌍 Real-World Usage Guide for Cloud Security Scanner

## For Real Users with Actual AWS Infrastructure

This guide explains how **real users** can scan their **actual AWS cloud infrastructure** using this security scanner.

---

## 📋 Prerequisites

Before you start, ensure you have:

1. **AWS Account** with resources to scan
2. **AWS Credentials** with read permissions
3. **Python 3.8+** installed
4. **boto3** library: `pip install boto3`

---

## 🚀 Step-by-Step: Scan Your Real AWS Infrastructure

### **Step 1: Install boto3**

```bash
pip install boto3
```

### **Step 2: Configure AWS Credentials**

Choose one of these methods:

#### **Option A: AWS CLI Configuration** (Recommended)
```bash
aws configure
```
Enter your:
- AWS Access Key ID
- AWS Secret Access Key
- Default region (e.g., `ap-south-1`)
- Output format (press Enter for default)

#### **Option B: Environment Variables**
```bash
# Windows (PowerShell)
$env:AWS_ACCESS_KEY_ID="your-access-key"
$env:AWS_SECRET_ACCESS_KEY="your-secret-key"
$env:AWS_DEFAULT_REGION="ap-south-1"

# Linux/Mac
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="ap-south-1"
```

#### **Option C: IAM Role** (For EC2 instances)
If running on EC2, attach an IAM role with read permissions.

---

### **Step 3: Run the Export Script**

The project includes a ready-to-use export script:

```bash
cd c:\Users\moham\Desktop\rohith\cloud-security-scanner-main
python export_aws_config.py
```

**What it does**:
- Connects to your AWS account
- Fetches all cloud resources:
  - ✓ S3 Buckets (encryption, public access, versioning, logging)
  - ✓ EC2 Instances (security groups, public IPs, EBS encryption)
  - ✓ RDS Databases (public access, encryption, backups)
  - ✓ IAM Users (MFA status, admin access, key rotation)
  - ✓ Lambda Functions (VPC config, encryption, tracing)
  - ✓ CloudTrail (logging status, validation, encryption)
- Analyzes security properties
- Generates `my-aws-config.json`

**Output**:
```
============================================================
AWS Cloud Configuration Exporter
============================================================
✓ Connected to AWS Account: 123456789012
✓ User ARN: arn:aws:iam::123456789012:user/admin

Exporting resources from region: ap-south-1
This may take a few minutes...

[1/6] Fetching S3 Buckets...
  - Analyzing bucket: my-production-bucket
  - Analyzing bucket: my-backup-bucket
  ✓ Found 2 S3 buckets

[2/6] Fetching EC2 Instances...
  - Analyzing instance: i-0abc123def456
  ✓ Found 3 EC2 instances

[3/6] Fetching RDS Databases...
  - Analyzing database: production-db
  ✓ Found 1 RDS databases

[4/6] Fetching IAM Users...
  - Analyzing user: admin
  - Analyzing user: developer
  ✓ Found 2 IAM users

[5/6] Fetching Lambda Functions...
  - Analyzing function: data-processor
  ✓ Found 5 Lambda functions

[6/6] Fetching CloudTrail Configuration...
  - Analyzing trail: main-trail
  ✓ Found 1 CloudTrail configurations

============================================================
✓ Export Complete!
✓ Total resources exported: 14
✓ Output file: my-aws-config.json
============================================================
```

---

### **Step 4: Review Generated JSON**

Open `my-aws-config.json` and review:

```json
{
  "cloud_provider": "AWS",
  "account_id": "123456789012",
  "scan_timestamp": "2026-01-19T10:27:00Z",
  "resources": [
    {
      "id": "s3-my-production-bucket",
      "type": "S3_Bucket",
      "name": "my-production-bucket",
      "region": "ap-south-1",
      "properties": {
        "public_access": true,
        "encryption": false,
        "versioning": false,
        "logging": false,
        "data_classification": "Internal",
        "contains_financial_data": false
      }
    }
    // ... more resources
  ]
}
```

**Important**: Update these fields based on your knowledge:
- `data_classification`: "PII", "Confidential", "Internal", or "Public"
- `contains_financial_data`: true/false

---

### **Step 5: Upload to Scanner**

1. **Ensure scanner is running**:
   ```bash
   python app.py
   ```
   Server starts at `http://localhost:5000`

2. **Open browser**: Navigate to `http://localhost:5000`

3. **Upload configuration**:
   - Click **"Upload Configuration"** button
   - Select `my-aws-config.json`
   - Click **"Upload"**

4. **Start scan**:
   - Click **"Start Scan"**
   - Wait for scan to complete (usually 10-30 seconds)

5. **View results**:
   - Dashboard shows all findings
   - ML risk scores (0-100)
   - Indian compliance violations
   - Detailed recommendations

---

## 🔒 Required AWS Permissions

The export script needs these **read-only** permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketEncryption",
        "s3:GetPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "rds:DescribeDBInstances",
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:ListAttachedUserPolicies",
        "iam:ListAccessKeys",
        "lambda:ListFunctions",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

**Note**: These are **read-only** permissions. The script cannot modify your AWS resources.

---

## 🌐 Multi-Region Scanning

To scan multiple regions, modify the script:

```python
# In export_aws_config.py, change:
REGIONS = ['ap-south-1', 'us-east-1', 'eu-west-1']

for region in REGIONS:
    all_resources.extend(fetch_s3_buckets(region))
    all_resources.extend(fetch_ec2_instances(region))
    # ... etc
```

---

## 🔄 Automated Daily Scans

For continuous monitoring, set up a scheduled task:

### **Windows (Task Scheduler)**
```powershell
# Create daily scan at 2 AM
$action = New-ScheduledTaskAction -Execute "python" -Argument "c:\path\to\export_aws_config.py"
$trigger = New-ScheduledTaskTrigger -Daily -At 2am
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "AWS Security Scan"
```

### **Linux (Cron)**
```bash
# Add to crontab
0 2 * * * cd /path/to/scanner && python export_aws_config.py && python upload_and_scan.py
```

---

## 📊 Real-World Example

### Company: XYZ Tech Pvt Ltd
**Infrastructure**: 50 resources across AWS

#### Day 1: Initial Scan
```bash
python export_aws_config.py
# Exported 50 resources

# Upload to scanner
# Results:
# - 23 security findings
# - 8 CRITICAL (ML score 85+)
# - 10 HIGH (ML score 70-84)
# - 5 MEDIUM (ML score 50-69)

# Compliance violations:
# - RBI: 6 violations
# - DPDP Act: 12 violations
# - CERT-In: 4 violations
# - IT Act: 8 violations
```

#### Actions Taken:
1. Enabled S3 bucket encryption (fixed 5 CRITICAL)
2. Enabled MFA for admin users (fixed 2 CRITICAL)
3. Removed public access from RDS (fixed 1 CRITICAL)
4. Enabled CloudTrail logging (fixed 3 HIGH)

#### Day 7: Re-scan
```bash
python export_aws_config.py
# Results:
# - 8 security findings (65% reduction!)
# - 0 CRITICAL
# - 3 HIGH
# - 5 MEDIUM
```

---

## 🎯 Best Practices

1. **Run weekly scans** to catch new misconfigurations
2. **Update data classifications** in JSON for accurate risk scoring
3. **Review ML scores** - prioritize 80+ scores first
4. **Track compliance** - ensure Indian regulations are met
5. **Document fixes** - keep audit trail of remediation
6. **Automate exports** - schedule regular scans

---

## ❓ Troubleshooting

### "AWS credentials not found"
**Solution**: Run `aws configure` or set environment variables

### "Access Denied" errors
**Solution**: Ensure IAM user has read permissions (see permissions section)

### "No resources found"
**Solution**: Check if you're scanning the correct region

### Script runs but JSON is empty
**Solution**: Verify AWS credentials have proper permissions

---

## 🔐 Security Notes

- Export script uses **read-only** permissions
- Credentials are **never** sent to the scanner
- JSON file contains **configuration only**, not data
- Store JSON files securely (contains infrastructure details)
- Rotate AWS access keys regularly

---

## 📞 Support

For issues or questions:
1. Check AWS credentials configuration
2. Verify IAM permissions
3. Review error messages in script output
4. Check scanner logs for upload errors

---

**You're now ready to scan your real AWS infrastructure!** 🚀
