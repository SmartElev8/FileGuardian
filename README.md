# Malware Detection System

## Overview
This is a machine learning-based malware detection system that can analyze files and URLs to identify potential malicious content. The system uses Random Forest classification to distinguish between legitimate and malicious files based on various extracted features.

## Supported File Types
The system can analyze the following types of files:
- Executable files (.exe)
- Dynamic Link Libraries (.dll)
- Windows System files (.sys)
- Script files (.vbs, .js, .ps1)
- Document files (.doc, .docx, .pdf)
- Archive files (.zip, .rar)
- Other binary files

## Features
1. **File Analysis**
   - Upload and analyze individual files
   - Real-time malware detection
   - Detailed analysis report

2. **URL Analysis**
   - Check URLs for potential malicious content
   - Domain reputation checking
   - Phishing detection

3. **Quarantine Management**
   - Isolate malicious files in a secure quarantine
   - View all quarantined files
   - Restore files from quarantine when needed
   - Permanently delete quarantined files

4. **Activity Tracking**
   - View scan history of all analyzed files
   - Track quarantine and restore actions
   - Monitor security activities on your device

5. **Batch Processing**
   - Analyze multiple files at once
   - Generate comprehensive reports

## Technical Details

### Feature Extraction
The system analyzes files based on various features including:
- File headers and metadata
- API calls and system interactions
- String patterns and signatures
- File structure characteristics
- Behavioral patterns
- Network activity patterns

### Machine Learning Model
- Uses Random Forest Classifier
- Trained on a large dataset of legitimate and malicious files
- Feature selection using ExtraTreesClassifier
- Regular model updates for improved detection

### Quarantine System
- Securely isolates malicious files
- Preserves original file path information
- Uses device ID for session tracking
- Maintains file metadata for easy management

## Usage

### Web Interface
1. Access the web interface at `http://localhost:5001`
2. Choose between file upload or URL analysis
3. Submit the file or URL for analysis
4. View the results and detailed report
5. Quarantine malicious files with one click
6. Access quarantine and activity history from the navigation menu

### API Usage
The system can also be used programmatically through its API endpoints:
- `/scan/file` - For file analysis
- `/scan/url` - For URL analysis
- `/quarantine/file/{scan_id}` - To quarantine a file
- `/quarantine/restore/{quarantine_id}` - To restore a file from quarantine
- `/quarantine/delete/{quarantine_id}` - To delete a file from quarantine

## Requirements
- Python 3.8 or higher
- Required Python packages (see requirements.txt):
  - flask
  - flask-sqlalchemy
  - numpy
  - pandas
  - scikit-learn
  - joblib
  - other dependencies

## Installation
1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
   python app.py
   ```

## Security Considerations
- Always scan files in a controlled environment
- Keep the system and dependencies updated
- Use the system as part of a comprehensive security strategy
- Do not rely solely on automated detection
- Regularly review your quarantine and scan history

## Limitations
- May not detect zero-day malware
- Performance depends on file size and type
- Some legitimate files might trigger false positives
- Requires regular model updates for optimal performance

## Contributing
Contributions are welcome! Please feel free to submit pull requests.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Support
For support, please open an issue in the repository or contact the maintainers.
