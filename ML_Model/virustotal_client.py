import requests
import time
import hashlib
import os
from typing import Dict, Optional, Union
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VirusTotalClient:
    def __init__(self, api_key: str):
        """
        Initialize VirusTotal client with API key
        """
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.headers = {
            "apikey": api_key,
            "Content-Type": "application/json"
        }
        self.last_request_time = 0
        self.min_request_interval = 15  # Minimum seconds between requests (VirusTotal's free tier limit)

    def _wait_for_rate_limit(self):
        """
        Implement rate limiting to respect VirusTotal's API limits
        """
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        
        if time_since_last_request < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last_request
            logger.info(f"Rate limiting: waiting {sleep_time:.2f} seconds")
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()

    def _calculate_file_hash(self, file_path: str) -> str:
        """
        Calculate SHA-256 hash of a file
        """
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def scan_file(self, file_path: str) -> Dict:
        """
        Submit a file for scanning
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        self._wait_for_rate_limit()
        
        try:
            # First, try to get existing report
            file_hash = self._calculate_file_hash(file_path)
            report = self.get_file_report(file_hash)
            
            if report.get('response_code') == 1:
                return report
            
            # If no report exists, submit the file
            files = {'file': open(file_path, 'rb')}
            response = requests.post(
                f"{self.base_url}/file/scan",
                headers=self.headers,
                files=files
            )
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error scanning file: {str(e)}")
            raise

    def get_file_report(self, resource: str) -> Dict:
        """
        Get a file report using its hash
        """
        self._wait_for_rate_limit()
        
        try:
            params = {'resource': resource}
            response = requests.get(
                f"{self.base_url}/file/report",
                headers=self.headers,
                params=params
            )
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting file report: {str(e)}")
            raise

    def analyze_report(self, report: Dict) -> Dict[str, Union[bool, float, str]]:
        """
        Analyze a VirusTotal report and return a simplified result
        """
        if report.get('response_code') != 1:
            return {
                'is_malicious': False,
                'confidence': 0.0,
                'message': 'No report available',
                'details': report
            }

        positives = report.get('positives', 0)
        total = report.get('total', 0)
        
        # Calculate confidence score (0-1)
        confidence = positives / total if total > 0 else 0
        
        # Consider file malicious if more than 5% of engines detect it
        is_malicious = confidence > 0.05
        
        # Get detailed scan results
        scans = report.get('scans', {})
        detailed_results = {
            engine: {
                'detected': result.get('detected', False),
                'result': result.get('result', 'N/A')
            }
            for engine, result in scans.items()
        }
        
        return {
            'is_malicious': is_malicious,
            'confidence': confidence,
            'message': f"Detected by {positives} out of {total} engines",
            'details': {
                'scan_date': report.get('scan_date'),
                'detailed_results': detailed_results,
                'sha256': report.get('sha256'),
                'md5': report.get('md5')
            }
        }

    def scan_and_analyze(self, file_path: str) -> Dict[str, Union[bool, float, str]]:
        """
        Scan a file and analyze its report in one step
        """
        try:
            # First try to get existing report
            file_hash = self._calculate_file_hash(file_path)
            report = self.get_file_report(file_hash)
            
            if report.get('response_code') == 1:
                return self.analyze_report(report)
            
            # If no report exists, submit the file
            scan_result = self.scan_file(file_path)
            
            # Wait for the scan to complete (usually takes a few minutes)
            logger.info("File submitted for scanning. Waiting for results...")
            time.sleep(60)  # Wait for initial scan
            
            # Get the final report
            report = self.get_file_report(file_hash)
            return self.analyze_report(report)
            
        except Exception as e:
            logger.error(f"Error in scan_and_analyze: {str(e)}")
            return {
                'is_malicious': False,
                'confidence': 0.0,
                'message': f'Error: {str(e)}',
                'details': {'error': str(e)}
            } 