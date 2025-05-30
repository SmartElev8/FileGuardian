from flask import Flask, request, jsonify, render_template
import os
from werkzeug.utils import secure_filename
import subprocess
import json
import datetime
import mimetypes
import re
from pathlib import Path
from ML_Model.virustotal_api import VirusTotalAPI
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'exe', 'pdf', 'docx'}  # Add PDF and DOCX to allowed extensions

# Initialize VirusTotal API
vt_api = VirusTotalAPI(api_key="49746271dbbd6d76591910613778dea3911cdc30506d531deadc24509d38c221")

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Ensure static directory exists
os.makedirs(os.path.join('static', 'images'), exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/documentation')
def documentation():
    return render_template('documentation.html')

@app.route('/api')
def api_docs():
    return render_template('api.html')

@app.route('/api-reference')
def api_reference():
    return render_template('api_reference.html')

@app.route('/faqs')
def faqs():
    return render_template('faqs.html')

@app.route('/threat-database')
def threat_database():
    return render_template('threat-database.html')

@app.route('/support')
def support():
    return render_template('support.html')

def get_file_details(filepath):
    """Extract detailed information from files, especially PDFs and DOCs"""
    file_path = Path(filepath)
    file_stats = os.stat(filepath)
    file_size = file_stats.st_size
    
    # Get basic file information
    details = {
        'file_size': file_size,
        'file_type': mimetypes.guess_type(filepath)[0] or 'Unknown',
        'created_date': datetime.datetime.fromtimestamp(file_stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
        'modified_date': datetime.datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
    }
    
    # Handle different file types
    file_extension = file_path.suffix.lower()
    
    # PDF Files
    if file_extension == '.pdf':
        try:
            # Simulating PDF analysis - in a real app, you'd use a library like PyPDF2 or pdfplumber
            # This is just sample data for demonstration
            details.update({
                'page_count': 8,  # Sample value
                'links_count': 15,  # Sample value
                'qr_codes_count': 2,  # Sample value
                'author': 'Document Author',  # Sample value
                'keywords': 'security, analysis, documentation',  # Sample value
                'subject': 'Security Analysis Report',  # Sample value
                'content_summary': f'This document appears to be a PDF file with multiple pages containing analysis information. The document includes hyperlinks and QR codes which have been analyzed for security threats. No malicious content was detected.'
            })
        except Exception as e:
            print(f"Error analyzing PDF: {str(e)}")
    
    # DOC/DOCX Files
    elif file_extension in ['.doc', '.docx']:
        try:
            # Simulating DOC analysis - in a real app, you'd use a library like python-docx
            # This is just sample data for demonstration
            details.update({
                'page_count': 5,  # Sample value
                'links_count': 8,  # Sample value
                'qr_codes_count': 0,  # Sample value
                'author': 'Document Author',  # Sample value
                'keywords': 'documentation, report, analysis',  # Sample value
                'subject': 'Technical Documentation',  # Sample value
                'content_summary': f'This document appears to be a Word document containing technical documentation. It includes several hyperlinks which have been analyzed for security threats. No malicious content was detected.'
            })
        except Exception as e:
            print(f"Error analyzing DOC: {str(e)}")
    
    # For all other file types, provide basic info
    else:
        # Extract info based on filename - in a real app, you'd analyze the actual content
        filename = file_path.stem
        words = re.findall(r'\w+', filename)
        title_case_words = [word.capitalize() for word in words]
        readable_name = ' '.join(title_case_words)
        
        details.update({
            'page_count': 'N/A',
            'links_count': 'N/A',
            'qr_codes_count': 'N/A',
            'content_summary': f'This file appears to be a {file_extension[1:].upper()} file named "{readable_name}". The file was scanned for malicious content and found to be safe.'
        })
    
    return details

def run_local_file_scan(filepath: str) -> dict:
    """Run local file scanning using existing models"""
    try:
        # Determine which scanner to use based on file extension
        file_extension = os.path.splitext(filepath)[1].lower()
        if file_extension in ['.pdf', '.docx']:
            scanner_script = 'Extract/document_scanner/document_main.py'
        else:
            scanner_script = 'Extract/PE_main.py'
        
        # Run the appropriate scanner
        result = subprocess.run(['python', scanner_script, filepath], 
                              capture_output=True, text=True)
        
        # Parse the result
        try:
            result_data = json.loads(result.stdout)
            is_malicious = result_data.get('is_malicious', False)
            message = result_data.get('message', 'Analysis completed')
            details = result_data.get('details', {})
        except json.JSONDecodeError:
            is_malicious = 'malicious' in result.stdout.lower()
            message = result.stdout
            details = {}
        
        return {
            'is_malicious': is_malicious,
            'message': message,
            'details': details,
            'scan_type': 'local'
        }
    except Exception as e:
        return {
            'is_malicious': False,
            'message': f'Error during local analysis: {str(e)}',
            'details': {'error': str(e)},
            'scan_type': 'local'
        }

def run_local_url_scan(url: str) -> dict:
    """Run local URL scanning using existing models"""
    try:
        result = subprocess.run(['python', 'Extract/url_main.py', url], 
                              capture_output=True, text=True)
        
        try:
            result_data = json.loads(result.stdout)
            is_malicious = result_data.get('is_malicious', False)
            message = result_data.get('message', 'Analysis completed')
            details = result_data.get('details', {})
        except json.JSONDecodeError:
            is_malicious = 'malicious' in result.stdout.lower()
            message = result.stdout
            details = {}
        
        return {
            'is_malicious': is_malicious,
            'message': message,
            'details': details,
            'scan_type': 'local'
        }
    except Exception as e:
        return {
            'is_malicious': False,
            'message': f'Error during local analysis: {str(e)}',
            'details': {'error': str(e)},
            'scan_type': 'local'
        }

@app.route('/scan/file', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    try:
        # First try VirusTotal API
        result = vt_api.scan_file(filepath)
        
        # If VirusTotal is unavailable or rate limited, fall back to local scanning
        if result.get('use_fallback', False):
            logger.info("Falling back to local scanning due to: " + result.get('error', 'Unknown error'))
            result = run_local_file_scan(filepath)
        
        # Clean up the uploaded file
        os.remove(filepath)
        
        return jsonify({
            'is_malicious': result.get('is_malicious', False),
            'message': result.get('message', 'File analysis completed'),
            'details': {
                'malicious_ratio': result.get('malicious_ratio', 0),
                'positives': result.get('positives', 0),
                'total': result.get('total', 0),
                'scan_date': result.get('scan_date'),
                'permalink': result.get('permalink'),
                'error': result.get('error'),
                'scan_type': result.get('scan_type', 'virustotal')
            },
            'file_name': filename
        })
    except Exception as e:
        return jsonify({
            'is_malicious': False,
            'message': f'Error during analysis: {str(e)}',
            'details': {'error': str(e)},
            'file_name': filename
        }), 500

@app.route('/scan/url', methods=['POST'])
def scan_url():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    try:
        # First try VirusTotal API
        result = vt_api.scan_url(url)
        
        # If VirusTotal is unavailable or rate limited, fall back to local scanning
        if result.get('use_fallback', False):
            logger.info("Falling back to local scanning due to: " + result.get('error', 'Unknown error'))
            result = run_local_url_scan(url)
        
        return jsonify({
            'is_malicious': result.get('is_malicious', False),
            'message': result.get('message', 'URL analysis completed'),
            'details': {
                'malicious_ratio': result.get('malicious_ratio', 0),
                'positives': result.get('positives', 0),
                'total': result.get('total', 0),
                'scan_date': result.get('scan_date'),
                'permalink': result.get('permalink'),
                'error': result.get('error'),
                'scan_type': result.get('scan_type', 'virustotal')
            },
            'url': url
        })
    except Exception as e:
        return jsonify({
            'is_malicious': False,
            'message': f'Error during analysis: {str(e)}',
            'details': {'error': str(e)},
            'url': url
        }), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001, debug=True) 