"""
ML Risk Predictor Module
Uses Random Forest Machine Learning to predict context-aware risk scores (0-100).
"""

import numpy as np
import os
import json
from typing import Dict, List, Any

# Try to import scikit-learn, fallback to rule-based if not available
try:
    from sklearn.ensemble import RandomForestRegressor
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("⚠️  scikit-learn not installed. Using rule-based fallback.")
    print("   Install with: pip install scikit-learn")

class MLRiskPredictor:
    """
    Machine Learning based risk predictor.
    Provides context-aware risk scores instead of static HIGH/MEDIUM/LOW.
    """
    
    def __init__(self):
        self.use_ml = SKLEARN_AVAILABLE
        self.model = None
        self.scaler = None
        self.feature_weights = self._initialize_weights()
        
        if self.use_ml:
            self._initialize_ml_model()
        else:
            print("[INFO] Using rule-based risk scoring (ML not available)")
        
    def _initialize_weights(self) -> Dict:
        """Initialize feature weights for risk calculation."""
        return {
            # Data sensitivity weights
            'data_sensitivity': {
                'PII': 1.0,
                'Confidential': 0.85,
                'Internal': 0.5,
                'Public': 0.1
            },
            # Severity base scores
            'severity_base': {
                'CRITICAL': 85,
                'HIGH': 70,
                'MEDIUM': 50,
                'LOW': 25
            },
            # Category multipliers
            'category_multiplier': {
                'Data Exposure': 1.3,
                'Encryption': 1.2,
                'Identity': 1.25,
                'Network Exposure': 1.15,
                'Logging': 0.9,
                'Data Protection': 1.1,
                'Availability': 0.85,
                'Web Security': 1.1,
                'Instance Security': 1.0,
                'Network Security': 1.1,
                'Least Privilege': 1.15
            },
            # Financial data bonus
            'financial_data_bonus': 15,
            # Internet exposure duration factor
            'exposure_duration_factor': 0.3,
            # Connected resources factor
            'connected_resources_factor': 2
        }
    
    def _initialize_ml_model(self):
        """Initialize and train Random Forest model."""
        print("[ML] Initializing Random Forest ML model...")
        
        # Create Random Forest Regressor
        self.model = RandomForestRegressor(
            n_estimators=100,  # 100 decision trees
            max_depth=10,
            random_state=42,
            n_jobs=-1  # Use all CPU cores
        )
        
        # Create scaler for feature normalization
        self.scaler = StandardScaler()
        
        # Generate training data and train model
        X_train, y_train = self._generate_training_data()
        X_scaled = self.scaler.fit_transform(X_train)
        self.model.fit(X_scaled, y_train)
        
        print("[SUCCESS] Random Forest model trained successfully!")
        print(f"   - Trees: {self.model.n_estimators}")
        print(f"   - Training samples: {len(X_train)}")
    
    def _generate_training_data(self):
        """Generate synthetic training data for Random Forest."""
        # Features: [severity_num, category_num, sensitivity_num, financial, pii, 
        #            public, days_public, admin, encryption]
        
        X_train = []
        y_train = []
        
        # Training examples based on security patterns
        training_examples = [
            # [severity, category, sensitivity, financial, pii, public, days, admin, encryption] -> risk_score
            ([85, 1.3, 1.0, 1, 1, 1, 30, 1, 0], 100),  # CRITICAL: Public S3 with PII+Financial
            ([85, 1.3, 1.0, 1, 1, 1, 60, 1, 0], 100),  # CRITICAL: Long exposure
            ([70, 1.3, 1.0, 0, 1, 1, 15, 0, 0], 88),   # HIGH: Public with PII
            ([70, 1.2, 0.85, 1, 0, 0, 0, 1, 0], 82),   # HIGH: No encryption, financial, admin
            ([70, 1.15, 0.5, 0, 0, 1, 5, 0, 1], 65),   # HIGH: Public but encrypted
            ([50, 1.25, 1.0, 0, 1, 0, 0, 1, 1], 68),   # MEDIUM: IAM with PII, admin
            ([50, 1.1, 0.5, 0, 0, 1, 10, 0, 0], 58),   # MEDIUM: Public, internal data
            ([50, 0.9, 0.5, 0, 0, 0, 0, 0, 1], 42),    # MEDIUM: Logging issue
            ([25, 1.1, 0.5, 0, 0, 0, 0, 0, 1], 28),    # LOW: Minor issue
            ([25, 0.85, 0.1, 0, 0, 0, 0, 0, 1], 18),   # LOW: Very minor
            
            # More examples for better training
            ([85, 1.3, 1.0, 1, 1, 0, 0, 1, 0], 95),    # CRITICAL: PII+Financial, admin, no encryption
            ([85, 1.25, 1.0, 0, 1, 1, 45, 1, 0], 98),  # CRITICAL: Long exposure with admin
            ([70, 1.3, 0.85, 1, 0, 1, 20, 0, 0], 78),  # HIGH: Financial data public
            ([70, 1.2, 1.0, 0, 1, 0, 0, 0, 0], 72),    # HIGH: PII no encryption
            ([70, 1.15, 0.5, 0, 0, 1, 30, 0, 0], 68),  # HIGH: Public for long time
            ([50, 1.25, 0.85, 0, 0, 0, 0, 1, 1], 55),  # MEDIUM: Admin access
            ([50, 1.1, 0.5, 0, 0, 1, 2, 0, 1], 48),    # MEDIUM: Recently public
            ([50, 1.0, 0.5, 0, 0, 0, 0, 0, 0], 45),    # MEDIUM: Standard issue
            ([25, 1.1, 0.5, 0, 0, 0, 0, 0, 1], 25),    # LOW: Minor config
            ([25, 0.9, 0.1, 0, 0, 0, 0, 0, 1], 15),    # LOW: Logging
            
            # Edge cases
            ([85, 1.3, 1.0, 1, 1, 1, 90, 1, 0], 100),  # Worst case
            ([25, 0.85, 0.1, 0, 0, 0, 0, 0, 1], 12),   # Best case
            ([70, 1.2, 1.0, 1, 1, 0, 0, 0, 0], 85),    # HIGH: PII+Financial, no public
            ([50, 1.15, 0.85, 0, 0, 1, 60, 0, 0], 62), # MEDIUM: Long public exposure
        ]
        
        for features, risk_score in training_examples:
            X_train.append(features)
            y_train.append(risk_score)
        
        return np.array(X_train), np.array(y_train)
    
    def _extract_features(self, finding: Dict) -> np.array:
        """Extract numerical features from finding for ML model."""
        props = finding.get('properties', {})
        severity = finding.get('severity', 'MEDIUM')
        category = finding.get('category', 'Other')
        
        # Map severity to number
        severity_map = {'CRITICAL': 85, 'HIGH': 70, 'MEDIUM': 50, 'LOW': 25}
        severity_num = severity_map.get(severity, 50)
        
        # Get category multiplier
        category_mult = self.feature_weights['category_multiplier'].get(category, 1.0)
        
        # Get sensitivity weight
        data_class = props.get('data_classification', 'Internal')
        sensitivity_num = self.feature_weights['data_sensitivity'].get(data_class, 0.5)
        
        # Extract binary features
        financial = 1 if (props.get('contains_financial_data') or props.get('handles_financial_data')) else 0
        pii = 1 if props.get('contains_pii') else 0
        public = 1 if (props.get('publicly_accessible') or props.get('public_access')) else 0
        admin = 1 if props.get('admin_access') else 0
        encryption = 1 if props.get('encryption', False) else 0
        
        # Get days public
        days_public = props.get('days_public', 0)
        
        # Return feature vector
        features = [severity_num, category_mult, sensitivity_num, financial, pii, 
                   public, days_public, admin, encryption]
        
        return np.array(features).reshape(1, -1)
    
    def predict_risk_score(self, finding: Dict) -> int:
        """
        Predict risk score (0-100) for a finding.
        Uses Random Forest ML if available, otherwise falls back to rule-based scoring.
        
        Considers:
        - Data sensitivity (PII, Financial, Public)
        - Internet exposure duration
        - Connected resources
        - Resource type importance
        - Base severity
        """
        
        # Use Random Forest ML if available
        if self.use_ml and self.model is not None:
            return self._predict_with_ml(finding)
        else:
            return self._predict_with_rules(finding)
    
    def _predict_with_ml(self, finding: Dict) -> int:
        """Predict risk score using Random Forest ML model."""
        try:
            # Extract features
            features = self._extract_features(finding)
            
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # Predict with Random Forest
            risk_score = self.model.predict(features_scaled)[0]
            
            # Normalize to 0-100 range
            risk_score = max(0, min(100, int(risk_score)))
            
            return risk_score
            
        except Exception as e:
            print(f"[WARNING] ML prediction failed: {e}. Using rule-based fallback.")
            return self._predict_with_rules(finding)
    
    def _predict_with_rules(self, finding: Dict) -> int:
        """Fallback rule-based risk prediction."""
        props = finding.get('properties', {})
        severity = finding.get('severity', 'MEDIUM')
        category = finding.get('category', 'Other')
        
        # Start with base severity score
        base_score = self.feature_weights['severity_base'].get(severity, 50)
        
        # Apply category multiplier
        category_mult = self.feature_weights['category_multiplier'].get(category, 1.0)
        score = base_score * category_mult
        
        # Data sensitivity adjustment
        data_class = props.get('data_classification', 'Internal')
        sensitivity_weight = self.feature_weights['data_sensitivity'].get(data_class, 0.5)
        score = score * (0.7 + 0.6 * sensitivity_weight)
        
        # Financial data bonus
        if props.get('contains_financial_data', False) or props.get('handles_financial_data', False):
            score += self.feature_weights['financial_data_bonus']
        
        # Contains PII bonus
        if props.get('contains_pii', False):
            score += 10
        
        # Internet exposure duration factor
        days_public = props.get('days_public', 0)
        if days_public > 0:
            duration_bonus = min(days_public * self.feature_weights['exposure_duration_factor'], 15)
            score += duration_bonus
        
        # Admin access risk
        if props.get('admin_access', False):
            score += 12
        
        # Public accessibility risk
        if props.get('publicly_accessible', False) or props.get('public_access', False):
            score += 8
        
        # Old access keys risk
        access_key_age = props.get('access_key_age_days', 0)
        if access_key_age > 180:
            score += 8
        elif access_key_age > 90:
            score += 4
        
        # Normalize to 0-100 range
        score = max(0, min(100, int(score)))
        
        return score
    
    def predict_all(self, findings: List[Dict]) -> List[Dict]:
        """Predict risk scores for all findings."""
        scored_findings = []
        
        for finding in findings:
            finding_copy = finding.copy()
            finding_copy['ml_risk_score'] = self.predict_risk_score(finding)
            finding_copy['risk_level'] = self._score_to_level(finding_copy['ml_risk_score'])
            scored_findings.append(finding_copy)
        
        # Sort by risk score descending
        scored_findings.sort(key=lambda x: x['ml_risk_score'], reverse=True)
        
        return scored_findings
    
    def _score_to_level(self, score: int) -> str:
        """Convert numeric score to risk level."""
        if score >= 80:
            return 'CRITICAL'
        elif score >= 60:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def get_risk_distribution(self, scored_findings: List[Dict]) -> Dict:
        """Get distribution of risk scores."""
        if not scored_findings:
            return {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'average_score': 0
            }
        
        distribution = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        total_score = 0
        for finding in scored_findings:
            score = finding.get('ml_risk_score', 0)
            total_score += score
            
            if score >= 80:
                distribution['critical'] += 1
            elif score >= 60:
                distribution['high'] += 1
            elif score >= 40:
                distribution['medium'] += 1
            else:
                distribution['low'] += 1
        
        distribution['average_score'] = round(total_score / len(scored_findings), 1)
        
        return distribution
    
    def explain_score(self, finding: Dict) -> Dict:
        """Explain why a particular score was given."""
        props = finding.get('properties', {})
        score = finding.get('ml_risk_score', 0)
        
        factors = []
        
        # Data sensitivity
        data_class = props.get('data_classification', '')
        if data_class:
            factors.append(f"Data Classification: {data_class}")
        
        if props.get('contains_financial_data', False):
            factors.append("Contains Financial Data (+15)")
        
        if props.get('contains_pii', False):
            factors.append("Contains PII (+10)")
        
        days_public = props.get('days_public', 0)
        if days_public > 0:
            factors.append(f"Publicly Exposed for {days_public} days")
        
        if props.get('admin_access', False):
            factors.append("Has Admin Access (+12)")
        
        access_key_age = props.get('access_key_age_days', 0)
        if access_key_age > 90:
            factors.append(f"Access Key Age: {access_key_age} days")
        
        return {
            'score': score,
            'level': self._score_to_level(score),
            'factors': factors,
            'category': finding.get('category', ''),
            'base_severity': finding.get('severity', '')
        }
