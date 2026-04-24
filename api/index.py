"""
Vercel Entry Point for Cloud Security Scanner Flask App
"""
import sys
import os

# Add parent directory to path so modules can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

# Vercel needs the app to be named 'app' or exported here
# This file serves as the WSGI handler
