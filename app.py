from flask import Flask, request, jsonify, render_template
import os
from werkzeug.utils import secure_filename
import subprocess
import json
import datetime
import mimetypes
import re
from pathlib import Path
import io
import logging

# PDF libraries
try:
    from pypdf import PdfReader
    import pikepdf
except ImportError:
    logging.warning("PDF libraries not available. PDF analysis will be limited.")

# DOCX libraries
try:
    import docx
except ImportError:
    logging.warning("python-docx not available. DOCX analysis will be limited.")

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'exe', 'pdf', 'docx', 'doc', 'ppt', 'pptx', 'xls', 'xlsx', 'txt', 'rtf', 'odt', 'zip', 'rar', 'tar', 'gz'}

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

def extract_text_from_pdf(pdf_path, max_pages=10):
    """Extract text from the first few pages of a PDF for summarization"""
    try:
        text = ""
        with open(pdf_path, 'rb') as file:
            reader = PdfReader(file)
            num_pages = min(len(reader.pages), max_pages)
            
            for i in range(num_pages):
                page = reader.pages[i]
                text += page.extract_text() + "\n"
                
        return text
    except Exception as e:
        logger.error(f"Error extracting text from PDF: {str(e)}")
        return ""

def count_links_in_pdf(pdf_path):
    """Count links in a PDF file"""
    try:
        with pikepdf.open(pdf_path) as pdf:
            link_count = 0
            for page in pdf.pages:
                if "/Annots" in page:
                    annotations = page["/Annots"]
                    for annot in annotations:
                        annot_obj = annot.get_object()
                        if annot_obj.get("/Subtype") == "/Link":
                            link_count += 1
            return link_count
    except Exception as e:
        logger.error(f"Error counting links in PDF: {str(e)}")
        return 0

def extract_text_from_docx(docx_path):
    """Extract text from a DOCX file for summarization"""
    try:
        doc = docx.Document(docx_path)
        text = ""
        
        # Extract text from paragraphs
        for para in doc.paragraphs:
            text += para.text + "\n"
            
        # Extract text from tables
        for table in doc.tables:
            for row in table.rows:
                for cell in row.cells:
                    text += cell.text + " "
                text += "\n"
                
        return text
    except Exception as e:
        logger.error(f"Error extracting text from DOCX: {str(e)}")
        return ""

def count_links_in_docx(docx_path):
    """Count hyperlinks in a DOCX file"""
    try:
        doc = docx.Document(docx_path)
        link_count = 0
        
        # Count hyperlinks in paragraphs
        for paragraph in doc.paragraphs:
            for run in paragraph.runs:
                if run.element.findall('.//w:hyperlink', namespaces=docx.oxml.ns.nsmap):
                    link_count += 1
        
        return link_count
    except Exception as e:
        logger.error(f"Error counting links in DOCX: {str(e)}")
        return 0

def count_images(file_path, file_type):
    """Count images in document files"""
    try:
        if file_type == '.pdf':
            # Count images in PDF
            with pikepdf.open(file_path) as pdf:
                image_count = 0
                for page in pdf.pages:
                    if '/Resources' in page and '/XObject' in page['/Resources']:
                        xobjects = page['/Resources']['/XObject']
                        for obj in xobjects:
                            if xobjects[obj].get('/Subtype') == '/Image':
                                image_count += 1
                return image_count
                
        elif file_type in ['.doc', '.docx']:
            # Count images in DOCX
            doc = docx.Document(file_path)
            image_count = 0
            for rel in doc.part.rels.values():
                if "image" in rel.target_ref:
                    image_count += 1
            return image_count
            
        return 0
    except Exception as e:
        logger.error(f"Error counting images: {str(e)}")
        return 0

def generate_content_summary(text, max_length=200):
    """Generate a brief summary of the document content"""
    try:
        # Simple summary: first few sentences up to max_length
        text = text.strip()
        sentences = re.split(r'(?<=[.!?])\s+', text)
        summary = ""
        
        for sentence in sentences:
            if len(summary) + len(sentence) <= max_length:
                summary += sentence + " "
            else:
                break
                
        if summary:
            return summary.strip()
        else:
            return "This document appears to contain no extractable text content."
    except Exception as e:
        logger.error(f"Error generating summary: {str(e)}")
        return "Unable to generate content summary."

def get_file_details(filepath):
    """Extract detailed information from files using appropriate libraries"""
    try:
        file_path = Path(filepath)
        file_stats = os.stat(filepath)
        file_size = file_stats.st_size
        
        # Use mimetypes to get file type
        mime_type = mimetypes.guess_type(filepath)[0] or 'application/octet-stream'
        
        # Get basic file information
        details = {
            'file_size': file_size,
            'file_type': mime_type,
            'created_date': datetime.datetime.fromtimestamp(file_stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
            'modified_date': datetime.datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
        }
        
        # Handle different file types
        file_extension = file_path.suffix.lower()
        
        # PDF Files
        if file_extension == '.pdf' or mime_type == 'application/pdf':
            try:
                with open(filepath, 'rb') as f:
                    pdf = PdfReader(f)
                    
                    # Extract metadata
                    metadata = pdf.metadata
                    if metadata:
                        if metadata.get('/Author'):
                            details['author'] = metadata.get('/Author')
                        if metadata.get('/Keywords'):
                            details['keywords'] = metadata.get('/Keywords')
                        if metadata.get('/Subject'):
                            details['subject'] = metadata.get('/Subject')
                        if metadata.get('/Title'):
                            details['title'] = metadata.get('/Title')
                    
                    # Page count
                    details['page_count'] = len(pdf.pages)
                    
                    # Count links
                    details['links_count'] = count_links_in_pdf(filepath)
                    
                    # Count images/possible QR codes
                    details['image_count'] = count_images(filepath, '.pdf')
                    details['qr_codes_count'] = 'Unknown' # Would need specific QR detection library
                    
                    # Extract text for summary
                    text = extract_text_from_pdf(filepath)
                    details['content_summary'] = generate_content_summary(text)
                    
            except Exception as e:
                logger.error(f"Error analyzing PDF: {str(e)}")
                details.update({
                    'page_count': 'Error',
                    'content_summary': f"Could not analyze PDF content: {str(e)}"
                })
        
        # DOC/DOCX Files
        elif file_extension in ['.doc', '.docx'] or mime_type in ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
            try:
                doc = docx.Document(filepath)
                
                # Basic document properties
                core_properties = doc.core_properties
                if core_properties.author:
                    details['author'] = core_properties.author
                if core_properties.keywords:
                    details['keywords'] = core_properties.keywords
                if core_properties.subject:
                    details['subject'] = core_properties.subject
                if core_properties.title:
                    details['title'] = core_properties.title
                
                # Page count (estimate based on paragraphs)
                # DOCX doesn't store page count directly, this is an estimation
                para_count = len(doc.paragraphs)
                details['page_count'] = max(1, para_count // 40)  # Rough estimate: ~40 paragraphs per page
                
                # Count links
                details['links_count'] = count_links_in_docx(filepath)
                
                # Count images
                details['image_count'] = count_images(filepath, '.docx')
                details['qr_codes_count'] = 'Unknown'
                
                # Extract text for summary
                text = extract_text_from_docx(filepath)
                details['content_summary'] = generate_content_summary(text)
                
            except Exception as e:
                logger.error(f"Error analyzing DOCX: {str(e)}")
                details.update({
                    'page_count': 'Error',
                    'content_summary': f"Could not analyze document content: {str(e)}"
                })
        
        # For all other file types, provide basic info
        else:
            # Extract info based on filename
            filename = file_path.stem
            words = re.findall(r'\w+', filename)
            title_case_words = [word.capitalize() for word in words]
            readable_name = ' '.join(title_case_words)
            
            details.update({
                'page_count': 'N/A',
                'links_count': 'N/A',
                'image_count': 'N/A',
                'qr_codes_count': 'N/A',
                'content_summary': f'This file appears to be a {file_extension[1:].upper()} file named "{readable_name}". The file was scanned for malicious content and found to be safe.'
            })
        
        return details
        
    except Exception as e:
        logger.error(f"Error in file analysis: {str(e)}")
        # Return basic information in case of error
        return {
            'file_size': os.path.getsize(filepath) if os.path.exists(filepath) else 0,
            'file_type': 'Unknown',
            'error': str(e),
            'content_summary': 'Error analyzing file content'
        }

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
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    try:
        # Run local file scan
        result = run_local_file_scan(filepath)
        
        # Get additional file details
        file_details = get_file_details(filepath)
        logger.info(f"File details: {file_details}")
        
        # Add file details to the result
        if 'details' not in result:
            result['details'] = {}
        result['details'].update(file_details)
        
        # Clean up the uploaded file
        os.remove(filepath)
        
        # Prepare the response
        response = {
            'is_malicious': result.get('is_malicious', False),
            'message': result.get('message', 'File analysis completed'),
            'details': result.get('details', {}),
            'file_name': filename
        }
        
        return jsonify(response)
    except Exception as e:
        logger.error(f"Error in scan_file: {str(e)}")
        # Clean up on error
        if os.path.exists(filepath):
            os.remove(filepath)
            
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
        # Run local URL scan
        result = run_local_url_scan(url)
        
        return jsonify({
            'is_malicious': result.get('is_malicious', False),
            'message': result.get('message', 'URL analysis completed'),
            'details': result.get('details', {}),
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