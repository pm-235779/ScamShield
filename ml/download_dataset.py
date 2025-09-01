#!/usr/bin/env python3
"""
Dataset downloader for APK malware detection
Downloads labeled APK datasets from various sources
"""

import os
import requests
import pandas as pd
import hashlib
from pathlib import Path
from typing import List, Dict, Any
import logging
from urllib.parse import urlparse
import zipfile
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DatasetDownloader:
    """Download and organize APK datasets for training"""
    
    def __init__(self, data_dir: str = "./data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        # Dataset sources (using publicly available datasets)
        self.dataset_sources = {
            "drebin": {
                "url": "https://www.sec.cs.tu-bs.de/~danarp/drebin/download.html",
                "description": "Drebin malware dataset",
                "type": "malware",
                "format": "features"  # Pre-extracted features
            },
            "androzoo_sample": {
                "description": "Sample benign APKs metadata",
                "type": "benign",
                "format": "metadata"
            }
        }
    
    def create_sample_dataset(self):
        """Create a sample dataset for demonstration purposes"""
        logger.info("Creating sample dataset for demonstration...")
        
        # Create sample malware features
        malware_samples = []
        for i in range(100):
            sample = {
                'apk_hash': hashlib.md5(f'malware_{i}'.encode()).hexdigest(),
                'dangerous_permissions': np.random.randint(3, 15),
                'total_permissions': np.random.randint(10, 30),
                'permission_ratio': np.random.uniform(0.3, 0.8),
                'activities_count': np.random.randint(5, 25),
                'services_count': np.random.randint(2, 15),
                'receivers_count': np.random.randint(1, 10),
                'providers_count': np.random.randint(0, 5),
                'min_sdk': np.random.randint(16, 23),
                'target_sdk': np.random.randint(23, 30),
                'has_self_signed_cert': np.random.choice([0, 1], p=[0.3, 0.7]),
                'cert_count': 1,
                'banking_keywords': np.random.randint(1, 5),
                'suspicious_strings': np.random.randint(2, 8),
                'perm_system': np.random.randint(1, 5),
                'perm_communication': np.random.randint(1, 4),
                'perm_location': np.random.randint(0, 3),
                'perm_media': np.random.randint(0, 2),
                'perm_contacts': np.random.randint(0, 2),
                'perm_storage': np.random.randint(0, 2),
                'perm_other': np.random.randint(0, 5),
                'label': 1  # Malware
            }
            malware_samples.append(sample)
        
        # Create sample benign features
        benign_samples = []
        for i in range(150):
            sample = {
                'apk_hash': hashlib.md5(f'benign_{i}'.encode()).hexdigest(),
                'dangerous_permissions': np.random.randint(0, 5),
                'total_permissions': np.random.randint(5, 20),
                'permission_ratio': np.random.uniform(0.0, 0.3),
                'activities_count': np.random.randint(3, 15),
                'services_count': np.random.randint(1, 8),
                'receivers_count': np.random.randint(0, 5),
                'providers_count': np.random.randint(0, 3),
                'min_sdk': np.random.randint(21, 26),
                'target_sdk': np.random.randint(26, 33),
                'has_self_signed_cert': np.random.choice([0, 1], p=[0.8, 0.2]),
                'cert_count': 1,
                'banking_keywords': np.random.randint(0, 2),
                'suspicious_strings': np.random.randint(0, 2),
                'perm_system': np.random.randint(0, 2),
                'perm_communication': np.random.randint(0, 2),
                'perm_location': np.random.randint(0, 2),
                'perm_media': np.random.randint(0, 2),
                'perm_contacts': np.random.randint(0, 1),
                'perm_storage': np.random.randint(0, 1),
                'perm_other': np.random.randint(0, 3),
                'label': 0  # Benign
            }
            benign_samples.append(sample)
        
        # Combine and save
        all_samples = malware_samples + benign_samples
        df = pd.DataFrame(all_samples)
        
        # Save features dataset
        features_path = self.data_dir / "features.parquet"
        df.to_parquet(features_path, index=False)
        
        # Save manifest
        manifest = {
            'total_samples': len(all_samples),
            'malware_samples': len(malware_samples),
            'benign_samples': len(benign_samples),
            'features_file': str(features_path),
            'feature_columns': list(df.columns),
            'created_at': pd.Timestamp.now().isoformat(),
            'source': 'synthetic_sample'
        }
        
        manifest_path = self.data_dir / "dataset_manifest.json"
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        logger.info(f"Sample dataset created: {len(all_samples)} samples")
        logger.info(f"Features saved to: {features_path}")
        logger.info(f"Manifest saved to: {manifest_path}")
        
        return features_path, manifest_path
    
    def download_real_datasets(self):
        """Download real datasets (placeholder for actual implementation)"""
        logger.info("Real dataset download not implemented in demo")
        logger.info("In production, this would:")
        logger.info("1. Download from Kaggle Android malware datasets")
        logger.info("2. Access AndroZoo with proper API credentials")
        logger.info("3. Collect benign APKs from APKMirror/F-Droid")
        logger.info("4. Respect ToS and licensing requirements")
        
        # Create placeholder for real dataset integration
        readme_content = """
# Real Dataset Integration

To use real datasets in production:

## 1. Kaggle Datasets
- Android Malware Dataset: https://www.kaggle.com/datasets/shashwatwork/android-malware-dataset
- Malware Detection Dataset: https://www.kaggle.com/datasets/xwolf12/malware-detection
- Use Kaggle API: `kaggle datasets download -d <dataset-name>`

## 2. AndroZoo
- Register at: https://androzoo.uni.lu/
- Get API key and follow their access policy
- Download samples with proper attribution

## 3. Benign APKs
- F-Droid: https://f-droid.org/ (open source apps)
- APKMirror: https://www.apkmirror.com/ (check ToS)
- Google Play Store (with proper tools and permissions)

## 4. Implementation Notes
- Always respect copyright and ToS
- Store only metadata/features, not original APKs
- Implement proper data validation and cleaning
- Use stratified sampling for balanced datasets
"""
        
        readme_path = self.data_dir / "REAL_DATASETS.md"
        with open(readme_path, 'w') as f:
            f.write(readme_content)
        
        return readme_path

if __name__ == "__main__":
    import numpy as np
    
    downloader = DatasetDownloader()
    
    # Create sample dataset for demonstration
    features_path, manifest_path = downloader.create_sample_dataset()
    
    # Create real dataset integration guide
    readme_path = downloader.download_real_datasets()
    
    print(f"\nDataset preparation complete!")
    print(f"Sample features: {features_path}")
    print(f"Manifest: {manifest_path}")
    print(f"Real dataset guide: {readme_path}")
