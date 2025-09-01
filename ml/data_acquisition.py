"""
Data Acquisition Scripts for Banking Trojan Detection
Downloads malware and benign APK samples from various sources including MalwareBazaar, Koodous, and APKMirror.
"""

import requests
import json
import os
import time
import hashlib
from typing import List, Dict
import zipfile
from urllib.parse import urlparse
import subprocess

class MalwareBazaarAPI:
    """Interface for MalwareBazaar API to download banking trojans."""
    
    BASE_URL = "https://mb-api.abuse.ch/api/v1/"
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'APKShield-Research-Tool'
        })
    
    def get_samples_by_tag(self, tag: str, limit: int = 100) -> List[Dict]:
        """Get malware samples by family tag (e.g., BankBot, Cerberus, Anatsa)."""
        data = {
            'query': 'get_taginfo',
            'tag': tag,
            'limit': str(limit)
        }
        
        try:
            response = self.session.post(self.BASE_URL, data=data)
            response.raise_for_status()
            result = response.json()
            
            if result.get('query_status') == 'ok':
                return result.get('data', [])
            else:
                print(f"API Error: {result.get('query_status')}")
                return []
                
        except Exception as e:
            print(f"Error fetching samples for tag {tag}: {e}")
            return []
    
    def download_sample(self, sha256_hash: str, output_dir: str) -> bool:
        """Download a malware sample by SHA256 hash."""
        data = {
            'query': 'get_file',
            'sha256_hash': sha256_hash
        }
        
        try:
            response = self.session.post(self.BASE_URL, data=data)
            response.raise_for_status()
            
            if response.headers.get('content-type') == 'application/zip':
                output_path = os.path.join(output_dir, f"{sha256_hash}.zip")
                with open(output_path, 'wb') as f:
                    f.write(response.content)
                
                # Extract the APK (password: infected)
                try:
                    with zipfile.ZipFile(output_path, 'r') as zip_ref:
                        zip_ref.extractall(output_dir, pwd=b'infected')
                    os.remove(output_path)  # Remove the zip file
                    return True
                except Exception as e:
                    print(f"Error extracting {sha256_hash}: {e}")
                    return False
            else:
                print(f"Unexpected content type for {sha256_hash}")
                return False
                
        except Exception as e:
            print(f"Error downloading {sha256_hash}: {e}")
            return False
    
    def download_banking_trojans(self, output_dir: str, samples_per_family: int = 50):
        """Download banking trojan samples from multiple families."""
        banking_families = ['BankBot', 'Cerberus', 'Anatsa', 'Teabot', 'Hydra', 'Ginp']
        
        os.makedirs(output_dir, exist_ok=True)
        
        total_downloaded = 0
        for family in banking_families:
            print(f"Downloading {family} samples...")
            samples = self.get_samples_by_tag(family, samples_per_family)
            
            family_downloaded = 0
            for sample in samples:
                if family_downloaded >= samples_per_family:
                    break
                    
                sha256 = sample.get('sha256_hash')
                if sha256:
                    if self.download_sample(sha256, output_dir):
                        family_downloaded += 1
                        total_downloaded += 1
                        print(f"Downloaded {family}: {sha256}")
                    
                    time.sleep(1)  # Rate limiting
            
            print(f"Downloaded {family_downloaded} {family} samples")
        
        print(f"Total downloaded: {total_downloaded} malware samples")

class APKMirrorDownloader:
    """Download benign banking apps from APKMirror."""
    
    # Popular banking apps for different regions
    BANKING_APPS = {
        'com.sbi.lotusintouch': 'State Bank of India',
        'com.icicibank.imobile': 'ICICI Bank iMobile',
        'com.hdfcbank.payzapp': 'HDFC Bank PayZapp',
        'com.axis.mobile': 'Axis Mobile',
        'com.kotakbank.mobilebanking': 'Kotak Mobile Banking',
        'net.one97.paytm': 'Paytm',
        'com.phonepe.app': 'PhonePe',
        'com.google.android.apps.nbu.paisa.user': 'Google Pay',
        'com.amazon.mShop.android.shopping': 'Amazon Shopping',
        'com.flipkart.android': 'Flipkart'
    }
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def create_sample_benign_apks(self, output_dir: str):
        """Create sample benign APK metadata (for demonstration purposes)."""
        os.makedirs(output_dir, exist_ok=True)
        
        # Create placeholder files representing benign apps
        for package_name, app_name in self.BANKING_APPS.items():
            # Create a simple text file as placeholder
            placeholder_path = os.path.join(output_dir, f"{package_name}.txt")
            with open(placeholder_path, 'w') as f:
                f.write(f"Placeholder for {app_name}\n")
                f.write(f"Package: {package_name}\n")
                f.write("Note: Replace with actual APK file downloaded from APKMirror\n")
                f.write("Always verify APK signatures before use!\n")
        
        print(f"Created {len(self.BANKING_APPS)} benign app placeholders in {output_dir}")
        print("Please manually download actual APK files from APKMirror and replace placeholders")

def download_cic_andmal_dataset():
    """Instructions for downloading CIC-AndMal2017 dataset."""
    print("""
    CIC-AndMal2017 Dataset Download Instructions:
    
    1. Visit: https://www.unb.ca/cic/datasets/andmal2017.html
    2. Fill out the request form for academic/research use
    3. Download the dataset files:
       - AndMal2017_static_features.csv
       - AndMal2017_dynamic_features.csv
       - Network traffic PCAPs
       - API call traces
    
    4. Extract to: ./data/cic_andmal2017/
    
    The dataset contains:
    - 426,000+ Android apps (benign + malware)
    - Static analysis features
    - Dynamic analysis traces
    - Network traffic captures
    - Labeled malware families
    """)

def setup_data_directories():
    """Create necessary data directories."""
    directories = [
        './data/malware_raw',
        './data/benign_raw',
        './data/processed',
        './data/cic_andmal2017',
        './data/traces'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"Created directory: {directory}")

def main():
    """Main data acquisition workflow."""
    print("APKShield ML Data Acquisition Tool")
    print("=" * 40)
    
    # Setup directories
    setup_data_directories()
    
    # Download malware samples
    print("\n1. Downloading malware samples from MalwareBazaar...")
    mb_api = MalwareBazaarAPI()
    mb_api.download_banking_trojans('./data/malware_raw', samples_per_family=20)
    
    # Create benign app placeholders
    print("\n2. Creating benign app placeholders...")
    apk_downloader = APKMirrorDownloader()
    apk_downloader.create_sample_benign_apks('./data/benign_raw')
    
    # CIC-AndMal dataset instructions
    print("\n3. CIC-AndMal2017 Dataset:")
    download_cic_andmal_dataset()
    
    print("\n" + "=" * 40)
    print("Data acquisition setup complete!")
    print("\nNext steps:")
    print("1. Manually download benign APKs from APKMirror")
    print("2. Request access to CIC-AndMal2017 dataset")
    print("3. Run feature extraction on collected samples")
    print("4. Train the ML model")

if __name__ == "__main__":
    main()
