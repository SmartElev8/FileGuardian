import requests
import hashlib
import time
import json
import os
from typing import Dict, Optional, Union, Tuple
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VirusTotalAPI:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.headers = {
            "apikey": api_key,
            "Content-Type": "application/json"
        }
        self.requests_remaining = 4  # Default to 4 requests per minute
        self.last_request_time = 0
    
    def _check_rate_limit(self) -> Tuple[bool, str]:
        """
        Check if we can make another API request
        Returns: (can_make_request, reason)
        """
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        
        if self.requests_remaining <= 0:
            if time_since_last_request < 60:  # Need to wait for a minute
                return False, "Rate limit exceeded. Please wait before making another request."
            else:
                self.requests_remaining = 4  # Reset counter after a minute
        
        return True, ""
    
    def _update_rate_limit(self):
        """Update rate limit tracking"""
        self.requests_remaining -= 1
        self.last_request_time = time.time()
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def scan_file(self, file_path: str) -> Dict[str, Union[bool, str, Dict]]:
        """
        Scan a file using VirusTotal API
        Returns a dictionary containing scan results
        """
        try:
            # Check rate limit
            can_request, reason = self._check_rate_limit()
            if not can_request:
                return {
                    "is_malicious": None,
                    "error": reason,
                    "use_fallback": True
                }
            
            # First, get the file hash
            file_hash = self._calculate_file_hash(file_path)
            
            # Check if the file has been previously scanned
            url = f"{self.base_url}/file/report"
            params = {"apikey": self.api_key, "resource": file_hash}
            
            response = requests.get(url, params=params)
            self._update_rate_limit()
            response.raise_for_status()
            result = response.json()
            
            # If the file hasn't been scanned before, submit it
            if result.get("response_code") == 0:
                logger.info(f"File {file_path} not found in VirusTotal database. Submitting for scanning...")
                
                # Check rate limit again before submitting
                can_request, reason = self._check_rate_limit()
                if not can_request:
                    return {
                        "is_malicious": None,
                        "error": reason,
                        "use_fallback": True
                    }
                
                # Submit file for scanning
                url = f"{self.base_url}/file/scan"
                files = {"file": open(file_path, "rb")}
                response = requests.post(url, files=files, headers=self.headers)
                self._update_rate_limit()
                response.raise_for_status()
                result = response.json()
                
                # Wait for scan to complete (VirusTotal has a rate limit)
                time.sleep(15)
                
                # Check rate limit before getting results
                can_request, reason = self._check_rate_limit()
                if not can_request:
                    return {
                        "is_malicious": None,
                        "error": reason,
                        "use_fallback": True
                    }
                
                # Get the scan results
                url = f"{self.base_url}/file/report"
                params = {"apikey": self.api_key, "resource": file_hash}
                response = requests.get(url, params=params)
                self._update_rate_limit()
                response.raise_for_status()
                result = response.json()
            
            # Process the results
            positives = result.get("positives", 0)
            total = result.get("total", 0)
            scans = result.get("scans", {})
            
            # Determine if the file is malicious based on the number of positive detections
            is_malicious = positives > 0
            malicious_ratio = positives / total if total > 0 else 0
            
            return {
                "is_malicious": is_malicious,
                "malicious_ratio": malicious_ratio,
                "positives": positives,
                "total": total,
                "scans": scans,
                "scan_date": result.get("scan_date"),
                "permalink": result.get("permalink"),
                "use_fallback": False
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error during VirusTotal API request: {str(e)}")
            return {
                "is_malicious": None,
                "error": str(e),
                "use_fallback": True
            }
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {
                "is_malicious": None,
                "error": str(e),
                "use_fallback": True
            }
    
    def scan_url(self, url: str) -> Dict[str, Union[bool, str, Dict]]:
        """
        Scan a URL using VirusTotal API
        Returns a dictionary containing scan results
        """
        try:
            # Check rate limit
            can_request, reason = self._check_rate_limit()
            if not can_request:
                return {
                    "is_malicious": None,
                    "error": reason,
                    "use_fallback": True
                }
            
            # Submit URL for scanning
            scan_url = f"{self.base_url}/url/scan"
            data = {"url": url}
            response = requests.post(scan_url, data=data, headers=self.headers)
            self._update_rate_limit()
            response.raise_for_status()
            result = response.json()
            
            # Wait for scan to complete
            time.sleep(15)
            
            # Check rate limit before getting results
            can_request, reason = self._check_rate_limit()
            if not can_request:
                return {
                    "is_malicious": None,
                    "error": reason,
                    "use_fallback": True
                }
            
            # Get the scan results
            report_url = f"{self.base_url}/url/report"
            params = {"apikey": self.api_key, "resource": url}
            response = requests.get(report_url, params=params)
            self._update_rate_limit()
            response.raise_for_status()
            result = response.json()
            
            # Process the results
            positives = result.get("positives", 0)
            total = result.get("total", 0)
            scans = result.get("scans", {})
            
            # Determine if the URL is malicious
            is_malicious = positives > 0
            malicious_ratio = positives / total if total > 0 else 0
            
            return {
                "is_malicious": is_malicious,
                "malicious_ratio": malicious_ratio,
                "positives": positives,
                "total": total,
                "scans": scans,
                "scan_date": result.get("scan_date"),
                "permalink": result.get("permalink"),
                "use_fallback": False
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error during VirusTotal API request: {str(e)}")
            return {
                "is_malicious": None,
                "error": str(e),
                "use_fallback": True
            }
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {
                "is_malicious": None,
                "error": str(e),
                "use_fallback": True
            } 