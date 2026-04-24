"""
Scanner Engine Module
Scans cloud resources against security rules to detect misconfigurations.
"""

import json
import os
from typing import Dict, List, Any

class ScannerEngine:
    """Scans cloud resources for security misconfigurations."""
    
    def __init__(self):
        self.rules = []
        self.findings = []
        self._load_rules()
    
    def _load_rules(self):
        """Load security rules from JSON file."""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        rules_file = os.path.join(base_dir, 'data', 'security_rules.json')
        
        try:
            with open(rules_file, 'r') as f:
                data = json.load(f)
                self.rules = data.get('rules', [])
        except Exception as e:
            print(f"Error loading security rules: {e}")
            self.rules = []
    
    def scan_resource(self, resource: Dict) -> List[Dict]:
        """Scan a single resource against all applicable rules."""
        findings = []
        resource_type = resource.get('type', '')
        
        for rule in self.rules:
            if rule.get('resource_type') != resource_type:
                continue
            
            if self._evaluate_rule(resource, rule):
                finding = {
                    'resource_id': resource.get('id'),
                    'resource_name': resource.get('name'),
                    'resource_type': resource_type,
                    'region': resource.get('region', 'unknown'),
                    'rule_id': rule.get('id'),
                    'rule_name': rule.get('name'),
                    'description': rule.get('description'),
                    'severity': rule.get('severity'),
                    'category': rule.get('category'),
                    'properties': resource.get('properties', {})
                }
                findings.append(finding)
        
        return findings
    
    def _evaluate_rule(self, resource: Dict, rule: Dict) -> bool:
        """Evaluate if a resource violates a rule."""
        condition = rule.get('condition', '')
        props = resource.get('properties', {})
        
        # Parse and evaluate condition
        try:
            # Simple condition parser
            if ' and ' in condition:
                parts = condition.split(' and ')
                return all(self._eval_single_condition(props, part.strip()) for part in parts)
            else:
                return self._eval_single_condition(props, condition)
        except Exception as e:
            print(f"Error evaluating rule {rule.get('id')}: {e}")
            return False
    
    def _eval_single_condition(self, props: Dict, condition: str) -> bool:
        """Evaluate a single condition expression."""
        # Handle == comparisons
        if ' == ' in condition:
            parts = condition.split(' == ')
            key = parts[0].replace('properties.', '').strip()
            expected = parts[1].strip()
            
            actual = props.get(key)
            
            if expected == 'true':
                return actual == True
            elif expected == 'false':
                return actual == False
            else:
                return str(actual) == expected
        
        # Handle > comparisons
        elif ' > ' in condition:
            parts = condition.split(' > ')
            key = parts[0].replace('properties.', '').strip()
            threshold = int(parts[1].strip())
            actual = props.get(key, 0)
            return actual > threshold
        
        # Handle < comparisons
        elif ' < ' in condition:
            parts = condition.split(' < ')
            key = parts[0].replace('properties.', '').strip()
            threshold = int(parts[1].strip())
            actual = props.get(key, 0)
            return actual < threshold
        
        return False
    
    def scan_all_resources(self, resources: List[Dict]) -> List[Dict]:
        """Scan all resources and collect findings."""
        self.findings = []
        
        for resource in resources:
            resource_findings = self.scan_resource(resource)
            self.findings.extend(resource_findings)
        
        return self.findings
    
    def get_findings_by_severity(self) -> Dict[str, List[Dict]]:
        """Group findings by severity level."""
        grouped = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': []
        }
        
        for finding in self.findings:
            severity = finding.get('severity', 'MEDIUM')
            if severity in grouped:
                grouped[severity].append(finding)
        
        return grouped
    
    def get_findings_by_category(self) -> Dict[str, List[Dict]]:
        """Group findings by category."""
        grouped = {}
        
        for finding in self.findings:
            category = finding.get('category', 'Other')
            if category not in grouped:
                grouped[category] = []
            grouped[category].append(finding)
        
        return grouped
    
    def get_summary(self) -> Dict:
        """Get scan summary statistics."""
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        for finding in self.findings:
            severity = finding.get('severity', 'MEDIUM')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            'total_findings': len(self.findings),
            'severity_counts': severity_counts,
            'unique_rules_triggered': len(set(f.get('rule_id') for f in self.findings)),
            'affected_resources': len(set(f.get('resource_id') for f in self.findings))
        }
