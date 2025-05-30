import os
import json
from docx import Document
from PyPDF2 import PdfReader
import re

def scan_document(file_path):
    """
    Scan a document (PDF or DOCX) for potential malicious content
    """
    file_extension = os.path.splitext(file_path)[1].lower()
    suspicious_patterns = [
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',  # URLs
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Email addresses
        r'(?i)(password|login|username|admin|root|system)',  # Sensitive terms
        r'(?i)(\.exe|\.bat|\.cmd|\.vbs|\.js|\.ps1)',  # Executable extensions
    ]
    
    try:
        content = ""
        if file_extension == '.pdf':
            content = extract_pdf_content(file_path)
        elif file_extension == '.docx':
            content = extract_docx_content(file_path)
        else:
            return {
                'is_malicious': False,
                'message': 'Unsupported file format',
                'details': {'error': 'Only PDF and DOCX files are supported'}
            }
        
        # Check for suspicious patterns
        findings = []
        for pattern in suspicious_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                findings.append({
                    'pattern': pattern,
                    'match': match.group(),
                    'position': match.start()
                })
        
        is_malicious = len(findings) > 0
        message = 'Document contains suspicious content' if is_malicious else 'Document appears to be safe'
        
        return {
            'is_malicious': is_malicious,
            'message': message,
            'details': {
                'findings': findings,
                'file_type': file_extension[1:].upper()
            }
        }
        
    except Exception as e:
        return {
            'is_malicious': False,
            'message': f'Error analyzing document: {str(e)}',
            'details': {'error': str(e)}
        }

def extract_pdf_content(file_path):
    """Extract text content from PDF file"""
    content = ""
    with open(file_path, 'rb') as file:
        pdf = PdfReader(file)
        for page in pdf.pages:
            content += page.extract_text() + "\n"
    return content

def extract_docx_content(file_path):
    """Extract text content from DOCX file"""
    doc = Document(file_path)
    content = ""
    for paragraph in doc.paragraphs:
        content += paragraph.text + "\n"
    return content

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        print(json.dumps({
            'is_malicious': False,
            'message': 'Please provide a file path',
            'details': {'error': 'No file path provided'}
        }))
        sys.exit(1)
    
    result = scan_document(sys.argv[1])
    print(json.dumps(result)) 