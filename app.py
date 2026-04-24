"""
Cloud Security Scanner - Main Flask Application
ML-based Cloud Misconfiguration Scanner with Indian Compliance Framework
"""

from flask import Flask, render_template, jsonify, request, session
import json
import time
import os
import uuid

from config import Config
from modules.cloud_connector import CloudConnector
from modules.scanner_engine import ScannerEngine
from modules.ml_predictor import MLRiskPredictor
from modules.compliance_mapper import ComplianceMapper
from modules.remediation_engine import RemediationEngine

app = Flask(__name__)
app.config.from_object(Config)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max file size

# Initialize modules
cloud_connector = CloudConnector(demo_mode=True)
scanner_engine = ScannerEngine()
ml_predictor = MLRiskPredictor()
compliance_mapper = ComplianceMapper()
remediation_engine = RemediationEngine(demo_mode=True)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers: /tmp-based scan result storage (works on Vercel serverless & local)
# ─────────────────────────────────────────────────────────────────────────────

TMP_DIR = '/tmp'


def _get_scan_id():
    """Get or create a unique scan ID stored in the session."""
    if 'scan_id' not in session:
        session['scan_id'] = str(uuid.uuid4())
    return session['scan_id']


def _scan_path(scan_id):
    return os.path.join(TMP_DIR, f'scan_{scan_id}.json')


def _upload_path(scan_id):
    return os.path.join(TMP_DIR, f'upload_{scan_id}.json')


def _load_scan_results(scan_id):
    path = _scan_path(scan_id)
    if os.path.exists(path):
        with open(path, 'r') as f:
            return json.load(f)
    return {
        'status': 'idle',
        'resources': [],
        'findings': [],
        'scored_findings': [],
        'compliance': {},
        'summary': {},
        'scan_mode': 'demo'
    }


def _save_scan_results(scan_id, data):
    os.makedirs(TMP_DIR, exist_ok=True)
    with open(_scan_path(scan_id), 'w') as f:
        json.dump(data, f)


def _load_uploaded(scan_id):
    path = _upload_path(scan_id)
    if os.path.exists(path):
        with open(path, 'r') as f:
            return json.load(f)
    return {'resources': [], 'cloud_info': {}}


def _save_uploaded(scan_id, data):
    os.makedirs(TMP_DIR, exist_ok=True)
    with open(_upload_path(scan_id), 'w') as f:
        json.dump(data, f)


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    """Redirect to login page."""
    return render_template('login.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle login page."""
    if request.method == 'POST':
        data = request.json if request.is_json else request.form
        demo_mode = data.get('demo_mode', True)

        scan_id = _get_scan_id()
        scan_results = _load_scan_results(scan_id)

        if demo_mode:
            session['logged_in'] = True
            session['demo_mode'] = True
            scan_results['scan_mode'] = 'demo'
            _save_scan_results(scan_id, scan_results)
            return jsonify({'success': True, 'redirect': '/scan'})

        return jsonify({'success': True, 'redirect': '/scan'})

    return render_template('login.html')


@app.route('/api/upload-config', methods=['POST'])
def upload_config():
    """Handle cloud configuration file upload."""
    if 'configFile' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'})

    file = request.files['configFile']

    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'})

    if not file.filename.endswith('.json'):
        return jsonify({'success': False, 'error': 'Only JSON files are supported'})

    try:
        content = file.read().decode('utf-8')
        data = json.loads(content)

        if 'resources' not in data:
            return jsonify({'success': False, 'error': 'Invalid format: missing "resources" array'})

        resources = data.get('resources', [])

        if not isinstance(resources, list) or len(resources) == 0:
            return jsonify({'success': False, 'error': 'Invalid format: "resources" must be a non-empty array'})

        for i, resource in enumerate(resources):
            if 'id' not in resource or 'type' not in resource or 'properties' not in resource:
                return jsonify({
                    'success': False,
                    'error': f'Resource at index {i} missing required fields (id, type, properties)'
                })

        scan_id = _get_scan_id()

        uploaded = {
            'resources': resources,
            'cloud_info': {
                'provider': data.get('cloud_provider', 'Custom'),
                'account_id': data.get('account_id', 'Uploaded Config'),
                'scan_timestamp': data.get('scan_timestamp', time.strftime('%Y-%m-%dT%H:%M:%SZ')),
                'demo_mode': False,
                'uploaded': True,
                'filename': file.filename
            }
        }
        _save_uploaded(scan_id, uploaded)

        scan_results = _load_scan_results(scan_id)
        scan_results['scan_mode'] = 'uploaded'
        _save_scan_results(scan_id, scan_results)

        session['logged_in'] = True
        session['demo_mode'] = False

        return jsonify({
            'success': True,
            'redirect': '/scan',
            'resources_count': len(resources),
            'filename': file.filename
        })

    except json.JSONDecodeError as e:
        return jsonify({'success': False, 'error': f'Invalid JSON: {str(e)}'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error processing file: {str(e)}'})


@app.route('/scan')
def scan_page():
    """Render the scanning page."""
    return render_template('scan.html')


@app.route('/api/start-scan', methods=['POST'])
def start_scan():
    """Start the cloud security scan."""
    scan_id = _get_scan_id()
    scan_results = _load_scan_results(scan_id)

    scan_results['status'] = 'connecting'
    _save_scan_results(scan_id, scan_results)

    use_uploaded = scan_results.get('scan_mode') == 'uploaded'
    uploaded = _load_uploaded(scan_id)

    if use_uploaded and len(uploaded.get('resources', [])) > 0:
        scan_results['status'] = 'fetching'
        resources = uploaded['resources']
        cloud_info = uploaded['cloud_info']
    else:
        if not cloud_connector.connect():
            return jsonify({'success': False, 'error': 'Failed to connect to cloud provider'})
        scan_results['status'] = 'fetching'
        resources = cloud_connector.fetch_resources()
        cloud_info = cloud_connector.get_cloud_info()

    scan_results['resources'] = resources
    scan_results['status'] = 'scanning'
    _save_scan_results(scan_id, scan_results)

    findings = scanner_engine.scan_all_resources(resources)
    scan_results['findings'] = findings
    scan_results['status'] = 'analyzing'
    _save_scan_results(scan_id, scan_results)

    scored_findings = ml_predictor.predict_all(findings)
    scan_results['scored_findings'] = scored_findings
    scan_results['status'] = 'compliance'
    _save_scan_results(scan_id, scan_results)

    compliance = compliance_mapper.map_findings_to_compliance(scored_findings)
    scan_results['compliance'] = compliance

    scan_results['summary'] = {
        'total_resources': len(resources),
        'total_findings': len(findings),
        'risk_distribution': ml_predictor.get_risk_distribution(scored_findings),
        'scanner_summary': scanner_engine.get_summary(),
        'compliance_summary': compliance_mapper.get_overall_compliance(),
        'cloud_info': cloud_info
    }

    scan_results['status'] = 'complete'
    _save_scan_results(scan_id, scan_results)

    return jsonify({'success': True, 'redirect': '/dashboard'})


@app.route('/api/scan-status')
def scan_status():
    """Get current scan status."""
    scan_id = _get_scan_id()
    scan_results = _load_scan_results(scan_id)
    return jsonify({
        'status': scan_results['status'],
        'resources_count': len(scan_results.get('resources', [])),
        'findings_count': len(scan_results.get('findings', []))
    })


@app.route('/dashboard')
def dashboard():
    """Render the main dashboard."""
    return render_template('dashboard.html')


@app.route('/api/dashboard-data')
def dashboard_data():
    """Get dashboard data."""
    scan_id = _get_scan_id()
    scan_results = _load_scan_results(scan_id)
    return jsonify({
        'summary': scan_results.get('summary', {}),
        'findings': scan_results.get('scored_findings', [])[:20],
        'compliance': scan_results.get('compliance', {}),
        'resources': scan_results.get('resources', [])
    })


@app.route('/api/findings')
def get_findings():
    """Get all findings with risk scores."""
    scan_id = _get_scan_id()
    scan_results = _load_scan_results(scan_id)
    return jsonify({
        'findings': scan_results.get('scored_findings', []),
        'total': len(scan_results.get('scored_findings', []))
    })


@app.route('/api/compliance/<framework>')
def get_compliance_detail(framework):
    """Get detailed compliance info for a framework."""
    scan_id = _get_scan_id()
    scan_results = _load_scan_results(scan_id)
    compliance = scan_results.get('compliance', {})
    framework_data = compliance.get(framework.upper(), {})
    return jsonify(framework_data)


@app.route('/api/export-report')
def export_report():
    """Export full report data for PDF generation."""
    scan_id = _get_scan_id()
    scan_results = _load_scan_results(scan_id)
    report = compliance_mapper.generate_compliance_report()
    cloud_info = scan_results.get('summary', {}).get('cloud_info', {})
    return jsonify({
        'report': report,
        'findings': scan_results.get('scored_findings', []),
        'summary': scan_results.get('summary', {}),
        'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'cloud_info': cloud_info
    })


@app.route('/api/sample-config')
def get_sample_config():
    """Return a sample configuration file for download."""
    sample = {
        "cloud_provider": "AWS",
        "account_id": "YOUR_ACCOUNT_ID",
        "scan_timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ'),
        "resources": [
            {
                "id": "s3-example",
                "type": "S3_Bucket",
                "name": "my-bucket-name",
                "region": "ap-south-1",
                "created_date": "2024-01-01",
                "properties": {
                    "public_access": True,
                    "encryption": False,
                    "versioning": False,
                    "logging": False,
                    "data_classification": "PII",
                    "contains_financial_data": True,
                    "days_public": 30
                }
            },
            {
                "id": "ec2-example",
                "type": "EC2_Instance",
                "name": "my-server",
                "region": "ap-south-1",
                "created_date": "2024-01-01",
                "properties": {
                    "public_ip": True,
                    "security_group_open": True,
                    "imdsv2_enforced": False,
                    "ebs_encryption": False,
                    "monitoring": True,
                    "instance_type": "t3.large",
                    "open_ports": [22, 80, 443]
                }
            }
        ]
    }
    return jsonify(sample)


@app.route('/report')
def report_page():
    """Render the report page."""
    return render_template('report.html')


@app.route('/api/remediation/info', methods=['POST'])
def get_remediation_info():
    """Get remediation action info for a finding."""
    data = request.json
    rule_id = data.get('rule_id')

    if not rule_id:
        return jsonify({'success': False, 'error': 'Missing rule_id'})

    action_info = remediation_engine.get_remediation_action(rule_id)
    is_remediable = remediation_engine.is_remediable(rule_id)

    return jsonify({
        'success': True,
        'remediable': is_remediable,
        'action': action_info
    })


@app.route('/api/remediate', methods=['POST'])
def remediate_finding():
    """Execute remediation for a finding."""
    data = request.json
    finding = data.get('finding')

    if not finding:
        return jsonify({'success': False, 'error': 'Missing finding data'})

    result = remediation_engine.remediate_finding(finding)
    return jsonify(result)


@app.route('/api/remediation/history')
def get_remediation_history():
    """Get remediation history."""
    history = remediation_engine.get_history()
    return jsonify({
        'success': True,
        'history': history,
        'count': len(history)
    })


if __name__ == '__main__':
    print("\n" + "="*60)
    print("  Cloud Security Scanner - ML-Based Risk Assessment")
    print("  Indian Compliance Framework (RBI, DPDP, CERT-In, IT Act)")
    print("="*60)
    print("\n  Starting server at http://localhost:5000")
    print("  Press Ctrl+C to stop\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
