#!/usr/bin/env python3
"""
Specific file test script
Test the exact same file on both systems
"""

import sys
import os
import subprocess
import json
import hashlib

def test_specific_file(file_path):
    """Test a specific file with all scanners"""
    results = {}
    
    # Get file hash
    if os.path.exists(file_path):
        with open(file_path, 'rb') as f:
            content = f.read()
            file_hash = hashlib.md5(content).hexdigest()
        results['file_hash'] = file_hash
        results['file_size'] = len(content)
    else:
        results['error'] = f"File not found: {file_path}"
        return results
    
    # Test with PE scanner
    try:
        result = subprocess.run(
            ['python', 'Extract/PE_main.py', file_path],
            capture_output=True, text=True, timeout=30
        )
        results['pe_scanner'] = {
            'return_code': result.returncode,
            'stdout': result.stdout.strip(),
            'stderr': result.stderr.strip()
        }
    except Exception as e:
        results['pe_scanner'] = {'error': str(e)}
    
    # Test with document scanner
    try:
        result = subprocess.run(
            ['python', 'Extract/document_scanner/document_main.py', file_path],
            capture_output=True, text=True, timeout=30
        )
        results['document_scanner'] = {
            'return_code': result.returncode,
            'stdout': result.stdout.strip(),
            'stderr': result.stderr.strip()
        }
    except Exception as e:
        results['document_scanner'] = {'error': str(e)}
    
    # Test with Flask app scan endpoint
    try:
        # This would require the Flask app to be running
        # For now, we'll test the local scan function
        result = subprocess.run(
            ['python', '-c', f'''
import sys
sys.path.append(".")
from app import run_local_file_scan
result = run_local_file_scan("{file_path}")
print(json.dumps(result))
'''],
            capture_output=True, text=True, timeout=30
        )
        results['flask_scan'] = {
            'return_code': result.returncode,
            'stdout': result.stdout.strip(),
            'stderr': result.stderr.strip()
        }
    except Exception as e:
        results['flask_scan'] = {'error': str(e)}
    
    return results

def main():
    if len(sys.argv) != 2:
        print("Usage: python test_file.py <file_path>")
        print("Example: python test_file.py quarantine/f9381207064d49d9a4562066ac2c0414.pdf")
        sys.exit(1)
    
    file_path = sys.argv[1]
    print(f"🔍 Testing file: {file_path}")
    print("=" * 60)
    
    results = test_specific_file(file_path)
    
    print("\n📊 Test Results:")
    print(json.dumps(results, indent=2))
    
    # Save results
    output_file = f"test_results_{os.path.basename(file_path)}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n💾 Results saved to: {output_file}")
    print("\n📋 Instructions:")
    print("1. Run this same command on your partner's system")
    print("2. Compare the JSON output files")
    print("3. Look for differences in scanner outputs")

if __name__ == "__main__":
    main()
