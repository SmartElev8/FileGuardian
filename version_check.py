#!/usr/bin/env python3
"""
Version compatibility checker
Ensures both systems have compatible package versions
"""

import sys
import subprocess
import json

def get_package_version(package_name):
    """Get exact version of a package"""
    try:
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'show', package_name],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.startswith('Version:'):
                    return line.split(':')[1].strip()
        return 'NOT_INSTALLED'
    except Exception:
        return 'ERROR'

def check_critical_packages():
    """Check versions of critical packages"""
    critical_packages = [
        'scikit-learn',
        'numpy', 
        'pandas',
        'joblib',
        'pefile'
    ]
    
    versions = {}
    for package in critical_packages:
        versions[package] = get_package_version(package)
    
    return versions

def test_model_compatibility():
    """Test if models can be loaded without warnings"""
    try:
        result = subprocess.run([
            sys.executable, '-c', '''
import warnings
warnings.filterwarnings('error')
import joblib
import pickle

# Try to load models
try:
    clf = joblib.load('Classifier/classifier.pkl')
    print("✅ classifier.pkl loaded successfully")
except Exception as e:
    print(f"❌ classifier.pkl failed: {e}")

try:
    features = pickle.loads(open('Classifier/features.pkl', 'rb').read())
    print("✅ features.pkl loaded successfully")
except Exception as e:
    print(f"❌ features.pkl failed: {e}")

try:
    with open("Classifier/pickel_model.pkl", 'rb') as f:
        lgr = pickle.load(f)
    print("✅ pickel_model.pkl loaded successfully")
except Exception as e:
    print(f"❌ pickel_model.pkl failed: {e}")

try:
    with open("Classifier/pickel_vector.pkl", 'rb') as f:
        vectorizer = pickle.load(f)
    print("✅ pickel_vector.pkl loaded successfully")
except Exception as e:
    print(f"❌ pickel_vector.pkl failed: {e}")
'''
        ], capture_output=True, text=True, timeout=30)
        
        return {
            'return_code': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr
        }
    except Exception as e:
        return {'error': str(e)}

def main():
    print("🔍 Version Compatibility Check")
    print("=" * 50)
    
    # Check package versions
    print("\n📦 Critical Package Versions:")
    versions = check_critical_packages()
    for package, version in versions.items():
        print(f"   {package}: {version}")
    
    # Test model compatibility
    print("\n🤖 Model Compatibility Test:")
    compatibility = test_model_compatibility()
    print(compatibility.get('stdout', 'No output'))
    if compatibility.get('stderr'):
        print(f"Errors: {compatibility.get('stderr')}")
    
    # Recommendations
    print("\n📋 Recommendations:")
    print("1. Both systems should have identical package versions")
    print("2. If scikit-learn versions differ, install the same version:")
    print("   pip install scikit-learn==1.3.0")
    print("3. If models fail to load, retrain them:")
    print("   python retrain_model.py")
    
    # Save results
    results = {
        'package_versions': versions,
        'model_compatibility': compatibility
    }
    
    with open('version_check.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n💾 Results saved to: version_check.json")

if __name__ == "__main__":
    main()
