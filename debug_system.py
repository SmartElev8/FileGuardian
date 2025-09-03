#!/usr/bin/env python3
"""
Debug script to identify differences between systems
Run this on both your system and your partner's system
"""

import sys
import os
import platform
import subprocess
import json
import hashlib
from pathlib import Path

def get_system_info():
    """Get detailed system information"""
    return {
        'python_version': sys.version,
        'platform': platform.platform(),
        'architecture': platform.architecture(),
        'processor': platform.processor(),
        'system': platform.system(),
        'release': platform.release()
    }

def get_package_versions():
    """Get versions of key packages"""
    packages = [
        'flask', 'werkzeug', 'python-dotenv', 'virustotal-python',
        'pypdf', 'pikepdf', 'docx', 'numpy', 'pandas', 
        'scikit-learn', 'joblib', 'flask-sqlalchemy', 'pefile'
    ]
    
    versions = {}
    for package in packages:
        try:
            module = __import__(package)
            versions[package] = getattr(module, '__version__', 'Unknown')
        except ImportError:
            versions[package] = 'NOT_INSTALLED'
    
    return versions

def get_model_hashes():
    """Get MD5 hashes of ML models to ensure they're identical"""
    model_files = [
        'Classifier/classifier.pkl',
        'Classifier/features.pkl',
        'Classifier/pickel_model.pkl',
        'Classifier/pickel_vector.pkl'
    ]
    
    hashes = {}
    for model_file in model_files:
        if os.path.exists(model_file):
            with open(model_file, 'rb') as f:
                content = f.read()
                hashes[model_file] = hashlib.md5(content).hexdigest()
        else:
            hashes[model_file] = 'FILE_NOT_FOUND'
    
    return hashes

def test_pe_scan():
    """Test PE scanning with a known file"""
    try:
        # Test the PE scanner directly
        result = subprocess.run(
            ['python', 'Extract/PE_main.py', 'test_files/sample_test.docx'],
            capture_output=True, text=True, timeout=10
        )
        return {
            'stdout': result.stdout,
            'stderr': result.stderr,
            'return_code': result.returncode
        }
    except Exception as e:
        return {'error': str(e)}

def test_document_scan():
    """Test document scanning"""
    try:
        result = subprocess.run(
            ['python', 'Extract/document_scanner/document_main.py', 'test_files/sample_test.pdf'],
            capture_output=True, text=True, timeout=10
        )
        return {
            'stdout': result.stdout,
            'stderr': result.stderr,
            'return_code': result.returncode
        }
    except Exception as e:
        return {'error': str(e)}

def test_url_scan():
    """Test URL scanning"""
    try:
        result = subprocess.run(
            ['python', 'Extract/url_main.py', 'https://example.com'],
            capture_output=True, text=True, timeout=10
        )
        return {
            'stdout': result.stdout,
            'stderr': result.stderr,
            'return_code': result.returncode
        }
    except Exception as e:
        return {'error': str(e)}

def main():
    print("🔍 SmartFileGuardian System Comparison")
    print("=" * 60)
    
    # System information
    print("\n🖥️  System Information:")
    system_info = get_system_info()
    for key, value in system_info.items():
        print(f"   {key}: {value}")
    
    # Package versions
    print("\n📦 Package Versions:")
    package_versions = get_package_versions()
    for package, version in package_versions.items():
        print(f"   {package}: {version}")
    
    # Model hashes
    print("\n🤖 ML Model Hashes:")
    model_hashes = get_model_hashes()
    for model_file, hash_value in model_hashes.items():
        print(f"   {model_file}: {hash_value}")
    
    # Test scans
    print("\n🧪 Scanner Tests:")
    
    print("\n   PE Scanner Test:")
    pe_test = test_pe_scan()
    print(f"   Return Code: {pe_test.get('return_code', 'N/A')}")
    print(f"   Output: {pe_test.get('stdout', 'N/A')[:200]}...")
    
    print("\n   Document Scanner Test:")
    doc_test = test_document_scan()
    print(f"   Return Code: {doc_test.get('return_code', 'N/A')}")
    print(f"   Output: {doc_test.get('stdout', 'N/A')[:200]}...")
    
    print("\n   URL Scanner Test:")
    url_test = test_url_scan()
    print(f"   Return Code: {url_test.get('return_code', 'N/A')}")
    print(f"   Output: {url_test.get('stdout', 'N/A')[:200]}...")
    
    # Save results to file
    results = {
        'system_info': system_info,
        'package_versions': package_versions,
        'model_hashes': model_hashes,
        'pe_test': pe_test,
        'doc_test': doc_test,
        'url_test': url_test
    }
    
    with open('system_debug_info.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n💾 Debug information saved to: system_debug_info.json")
    print("\n📋 Instructions:")
    print("1. Run this script on both systems: python debug_system.py")
    print("2. Compare the system_debug_info.json files")
    print("3. Look for differences in package versions and model hashes")

if __name__ == "__main__":
    main()
