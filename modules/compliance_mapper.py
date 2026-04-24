"""
Compliance Mapper Module
Maps security findings to Indian regulatory frameworks.
"""

import json
import os
from typing import Dict, List, Any

class ComplianceMapper:
    """Maps security findings to Indian compliance frameworks."""
    
    def __init__(self):
        self.frameworks = {}
        self.compliance_results = {}
        self._load_compliance_rules()
    
    def _load_compliance_rules(self):
        """Load compliance rules from JSON file."""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        rules_file = os.path.join(base_dir, 'data', 'compliance_rules.json')
        
        try:
            with open(rules_file, 'r') as f:
                data = json.load(f)
                self.frameworks = data.get('frameworks', {})
        except Exception as e:
            print(f"Error loading compliance rules: {e}")
            self.frameworks = {}
    
    def map_findings_to_compliance(self, findings: List[Dict]) -> Dict:
        """Map all findings to compliance frameworks."""
        # Get unique rule IDs from findings
        violated_rules = set(f.get('rule_id') for f in findings)
        
        results = {}
        
        for framework_id, framework in self.frameworks.items():
            framework_result = self._evaluate_framework(framework, violated_rules, findings)
            results[framework_id] = framework_result
        
        self.compliance_results = results
        return results
    
    def _evaluate_framework(self, framework: Dict, violated_rules: set, findings: List[Dict]) -> Dict:
        """Evaluate compliance status for a single framework."""
        rules = framework.get('rules', [])
        total_controls = len(rules)
        compliant_controls = 0
        violations = []
        
        for rule in rules:
            mapped_rules = rule.get('mapped_rules', [])
            rule_violated = False
            
            # Check if any mapped security rule was violated
            for sec_rule in mapped_rules:
                if sec_rule in violated_rules:
                    rule_violated = True
                    # Find the actual findings for this rule
                    related_findings = [f for f in findings if f.get('rule_id') == sec_rule]
                    for rf in related_findings:
                        violations.append({
                            'compliance_rule_id': rule.get('id'),
                            'clause': rule.get('clause'),
                            'requirement': rule.get('requirement'),
                            'finding': rf,
                            'severity': rule.get('severity', 'MEDIUM')
                        })
                    break
            
            if not rule_violated:
                compliant_controls += 1
        
        # Calculate compliance percentage
        compliance_pct = round((compliant_controls / total_controls) * 100, 1) if total_controls > 0 else 100
        
        return {
            'framework_name': framework.get('name'),
            'full_name': framework.get('full_name'),
            'penalty': framework.get('penalty'),
            'total_controls': total_controls,
            'compliant_controls': compliant_controls,
            'non_compliant_controls': total_controls - compliant_controls,
            'compliance_percentage': compliance_pct,
            'violations': violations,
            'status': self._get_compliance_status(compliance_pct)
        }
    
    def _get_compliance_status(self, percentage: float) -> str:
        """Get compliance status based on percentage."""
        if percentage >= 90:
            return 'COMPLIANT'
        elif percentage >= 70:
            return 'PARTIALLY_COMPLIANT'
        elif percentage >= 50:
            return 'AT_RISK'
        else:
            return 'NON_COMPLIANT'
    
    def get_overall_compliance(self) -> Dict:
        """Get overall compliance summary across all frameworks."""
        if not self.compliance_results:
            return {
                'average_compliance': 0,
                'frameworks_count': 0,
                'compliant_count': 0,
                'at_risk_count': 0
            }
        
        total_pct = 0
        compliant_count = 0
        at_risk_count = 0
        
        for result in self.compliance_results.values():
            total_pct += result.get('compliance_percentage', 0)
            status = result.get('status', '')
            
            if status == 'COMPLIANT':
                compliant_count += 1
            elif status in ['AT_RISK', 'NON_COMPLIANT']:
                at_risk_count += 1
        
        return {
            'average_compliance': round(total_pct / len(self.compliance_results), 1),
            'frameworks_count': len(self.compliance_results),
            'compliant_count': compliant_count,
            'at_risk_count': at_risk_count
        }
    
    def get_framework_details(self, framework_id: str) -> Dict:
        """Get detailed compliance info for a specific framework."""
        return self.compliance_results.get(framework_id, {})
    
    def get_all_violations(self) -> List[Dict]:
        """Get all compliance violations across frameworks."""
        all_violations = []
        
        for framework_id, result in self.compliance_results.items():
            for violation in result.get('violations', []):
                violation_copy = violation.copy()
                violation_copy['framework'] = framework_id
                violation_copy['framework_name'] = result.get('framework_name')
                all_violations.append(violation_copy)
        
        return all_violations
    
    def get_priority_violations(self) -> List[Dict]:
        """Get high-priority violations that need immediate attention."""
        all_violations = self.get_all_violations()
        
        # Filter for CRITICAL and HIGH severity
        priority = [v for v in all_violations if v.get('severity') in ['CRITICAL', 'HIGH']]
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        priority.sort(key=lambda x: severity_order.get(x.get('severity', 'LOW'), 3))
        
        return priority
    
    def generate_compliance_report(self) -> Dict:
        """Generate a comprehensive compliance report."""
        overall = self.get_overall_compliance()
        priority_violations = self.get_priority_violations()
        
        report = {
            'summary': overall,
            'frameworks': {},
            'priority_actions': [],
            'recommendations': []
        }
        
        # Add framework details
        for framework_id, result in self.compliance_results.items():
            report['frameworks'][framework_id] = {
                'name': result.get('framework_name'),
                'compliance': result.get('compliance_percentage'),
                'status': result.get('status'),
                'penalty': result.get('penalty'),
                'violations_count': len(result.get('violations', []))
            }
        
        # Add priority actions
        for violation in priority_violations[:5]:  # Top 5
            report['priority_actions'].append({
                'framework': violation.get('framework_name'),
                'clause': violation.get('clause'),
                'action': f"Fix: {violation.get('finding', {}).get('rule_name', 'Unknown')}",
                'resource': violation.get('finding', {}).get('resource_name', 'Unknown'),
                'severity': violation.get('severity')
            })
        
        # Generate recommendations
        if overall.get('average_compliance', 0) < 70:
            report['recommendations'].append("Immediate action required to meet compliance requirements")
        
        for framework_id, result in self.compliance_results.items():
            if result.get('compliance_percentage', 0) < 80:
                report['recommendations'].append(
                    f"Review {result.get('framework_name')} requirements - currently at {result.get('compliance_percentage')}%"
                )
        
        return report
