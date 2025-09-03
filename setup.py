#!/usr/bin/env python3
"""
Setup script for SmartFileGuardian
Validates environment and provides setup instructions
"""

import os
import sys
import subprocess
import importlib.util

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        print(f"   Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version}")
    return True

def check_required_packages():
    """Check if required packages are installed"""
    required_packages = [
        'flask', 'werkzeug', 'python-dotenv', 'virustotal-python',
        'pypdf', 'pikepdf', 'docx', 'numpy', 'pandas', 
        'scikit-learn', 'joblib', 'flask-sqlalchemy'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            importlib.import_module(package)
            print(f"✅ {package}")
        except ImportError:
            print(f"❌ {package} - MISSING")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\n📦 Install missing packages with:")
        print(f"   pip install -r requirements.txt")
        return False
    
    return True

def check_ml_models():
    """Check if ML models are present"""
    required_models = [
        'Classifier/classifier.pkl',
        'Classifier/features.pkl',
        'Classifier/pickel_model.pkl', 
        'Classifier/pickel_vector.pkl'
    ]
    
    missing_models = []
    for model_path in required_models:
        if os.path.exists(model_path):
            size = os.path.getsize(model_path)
            print(f"✅ {model_path} ({size:,} bytes)")
        else:
            print(f"❌ {model_path} - MISSING")
            missing_models.append(model_path)
    
    if missing_models:
        print(f"\n🤖 Missing ML models detected!")
        print(f"   These files are required for malware detection:")
        for model in missing_models:
            print(f"   - {model}")
        print(f"\n   Please ensure all trained models are present in the Classifier/ directory")
        return False
    
    return True

def check_directories():
    """Check if required directories exist"""
    required_dirs = ['uploads', 'quarantine', 'Classifier', 'Extract']
    
    for directory in required_dirs:
        if os.path.exists(directory):
            print(f"✅ Directory: {directory}/")
        else:
            print(f"❌ Directory: {directory}/ - MISSING")
            os.makedirs(directory, exist_ok=True)
            print(f"   Created: {directory}/")

def check_env_file():
    """Check if .env file exists"""
    if os.path.exists('.env'):
        print("✅ Environment file: .env")
        return True
    else:
        print("⚠️  Environment file: .env - NOT FOUND")
        print("   Create .env file with:")
        print("   VT_API_KEY=your_virustotal_api_key_here")
        print("   SECRET_KEY=your_secret_key_here")
        return False

def main():
    print("🔍 SmartFileGuardian Environment Check")
    print("=" * 50)
    
    # Check Python version
    print("\n🐍 Python Environment:")
    python_ok = check_python_version()
    
    # Check required packages
    print("\n📦 Required Packages:")
    packages_ok = check_required_packages()
    
    # Check directories
    print("\n📁 Directory Structure:")
    check_directories()
    
    # Check ML models
    print("\n🤖 Machine Learning Models:")
    models_ok = check_ml_models()
    
    # Check environment file
    print("\n🔧 Environment Configuration:")
    env_ok = check_env_file()
    
    # Summary
    print("\n" + "=" * 50)
    print("📋 Setup Summary:")
    
    if all([python_ok, packages_ok, models_ok]):
        print("✅ All components are ready!")
        print("🚀 You can now run: python app.py")
    else:
        print("❌ Some components are missing.")
        print("\n📝 Next steps:")
        if not packages_ok:
            print("   1. Install missing packages: pip install -r requirements.txt")
        if not models_ok:
            print("   2. Ensure ML models are in Classifier/ directory")
        if not env_ok:
            print("   3. Create .env file with required API keys")
        print("   4. Run this script again to verify setup")

if __name__ == "__main__":
    main()
