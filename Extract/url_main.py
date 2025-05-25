'''
URL scanning functionality for malware detection
'''

import pandas as pd
import numpy as np
import random
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import csr_matrix
from sklearn.linear_model import LogisticRegression
import pickle
import sys
import json

def sanitization(web):
    web = web.lower()
    token = []
    dot_token_slash = []
    raw_slash = str(web).split('/')
    for i in raw_slash:
        raw1 = str(i).split('-')
        slash_token = []
        for j in range(0,len(raw1)):
            raw2 = str(raw1[j]).split('.')
            slash_token = slash_token + raw2
        dot_token_slash = dot_token_slash + raw1 + slash_token
    token = list(set(dot_token_slash)) 
    if 'com' in token:
        token.remove('com')
    return token

def scan_url(url):
    # Using whitelist filter as the model fails in many legit cases
    whitelist = ['hackthebox.eu','root-me.org','gmail.com']
    
    if url in whitelist:
        return {
            'is_malicious': False,
            'message': 'URL is in whitelist',
            'details': {'whitelisted': True}
        }
    
    # Loading the model
    try:
        with open("Classifier/pickel_model.pkl", 'rb') as f1:
            lgr = pickle.load(f1)
        with open("Classifier/pickel_vector.pkl", 'rb') as f2:
            vectorizer = pickle.load(f2)
    except Exception as e:
        return {
            'is_malicious': False,
            'message': f'Error loading model: {str(e)}',
            'details': {'error': str(e)}
        }
    
    # Predicting
    try:
        x = vectorizer.transform([url])
        y_predict = lgr.predict(x)
        is_malicious = y_predict[0] == 'bad'
        
        return {
            'is_malicious': is_malicious,
            'message': 'URL is potentially malicious' if is_malicious else 'URL appears to be safe',
            'details': {'prediction': 'malicious' if is_malicious else 'safe'}
        }
    except Exception as e:
        return {
            'is_malicious': False,
            'message': f'Error during analysis: {str(e)}',
            'details': {'error': str(e)}
        }

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(json.dumps({
            'is_malicious': False,
            'message': 'Please provide a URL as argument',
            'details': {'error': 'Missing URL argument'}
        }))
        sys.exit(1)
        
    url = sys.argv[1]
    result = scan_url(url)
    print(json.dumps(result))

