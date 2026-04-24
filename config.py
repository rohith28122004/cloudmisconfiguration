"""Configuration settings for Cloud Security Scanner"""

import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'cloud-scanner-secret-key-2024'
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Session config - allow larger session data
    SESSION_COOKIE_SECURE = os.environ.get('VERCEL') is not None
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Demo mode - no real cloud credentials needed
    DEMO_MODE = True
    
    # Paths
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DATA_DIR = os.path.join(BASE_DIR, 'data')
    ML_DIR = os.path.join(BASE_DIR, 'ml')
    
    # Temp storage for scan results (works on Vercel /tmp)
    TMP_DIR = '/tmp'
    
    # Indian Compliance Frameworks
    COMPLIANCE_FRAMEWORKS = [
        'RBI Guidelines',
        'DPDP Act 2023',
        'CERT-In Rules',
        'IT Act 2000'
    ]
