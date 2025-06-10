import requests
import time
import json

class VirusTotalAPI:
    """
    A simple wrapper for the VirusTotal API used by SmartFileGuardian
    """
    
    def __init__(self, api_key=None):
        """
        Initialize the API wrapper with your VirusTotal API key
        """
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.headers = {
            "apikey": api_key,
            "Content-Type": "application/json"
        }
        self.requests_remaining = 4  # Default public API limit
        self.last_request_time = 0
        
    def scan_file(self, file_path):
        """
        Submit a file to be scanned by VirusTotal
        """
        url = f"{self.base_url}/file/scan"
        files = {'file': open(file_path, 'rb')}
        params = {'apikey': self.api_key}
        
        self._rate_limit()
        response = requests.post(url, files=files, params=params)
        
        return response.json() if response.status_code == 200 else None
        
    def get_file_report(self, resource):
        """
        Get the report for a previously scanned file
        """
        url = f"{self.base_url}/file/report"
        params = {'apikey': self.api_key, 'resource': resource}
        
        self._rate_limit()
        response = requests.get(url, params=params)
        
        return response.json() if response.status_code == 200 else None
        
    def scan_url(self, url_to_scan):
        """
        Submit a URL to be scanned by VirusTotal
        """
        url = f"{self.base_url}/url/scan"
        params = {'apikey': self.api_key, 'url': url_to_scan}
        
        self._rate_limit()
        response = requests.post(url, data=params)
        
        return response.json() if response.status_code == 200 else None
        
    def get_url_report(self, resource):
        """
        Get the report for a previously scanned URL
        """
        url = f"{self.base_url}/url/report"
        params = {'apikey': self.api_key, 'resource': resource}
        
        self._rate_limit()
        response = requests.get(url, params=params)
        
        return response.json() if response.status_code == 200 else None
        
    def _rate_limit(self):
        """
        Implement rate limiting for the VirusTotal API
        Public API is limited to 4 requests per minute
        """
        current_time = time.time()
        time_passed = current_time - self.last_request_time
        
        # If less than 60 seconds have passed since our last request
        if time_passed < 60 and self.requests_remaining <= 0:
            sleep_time = 60 - time_passed
            time.sleep(sleep_time)
            self.requests_remaining = 4
        
        # If more than 60 seconds have passed, reset the counter
        elif time_passed >= 60:
            self.requests_remaining = 4
        
        self.requests_remaining -= 1
        self.last_request_time = time.time() 