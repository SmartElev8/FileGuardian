from flask import Flask, request, jsonify, render_template
import os
from werkzeug.utils import secure_filename
import subprocess
import json

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def home():
    return render_template('index.html')

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
        # Run the PE scanner
        result = subprocess.run(['python', 'Extract/PE_main.py', filepath], 
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
            details = {}  # No raw_output
        
        # Clean up the uploaded file
        os.remove(filepath)
        
        return jsonify({
            'is_malicious': is_malicious,
            'message': message,
            'details': details,
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
        # Run the URL scanner
        result = subprocess.run(['python', 'Extract/url_main.py', url], 
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
            details = {}  # No raw_output
        
        return jsonify({
            'is_malicious': is_malicious,
            'message': message,
            'details': details,
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
    app.run(debug=True) 