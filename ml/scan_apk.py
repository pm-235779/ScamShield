"""
APK Scanner CLI - Banking Trojan Detection
Command-line interface for scanning APK files using the trained ML model.
"""

import sys
import argparse
import pandas as pd
import joblib
import json
from pathlib import Path
from typing import Dict, Optional
import warnings
warnings.filterwarnings('ignore')

from static_feature_extractor import extract_static_features
from dynamic_feature_extractor import create_mock_dynamic_features

class APKScanner:
    """CLI scanner for APK malware detection."""
    
    def __init__(self, model_dir: str = "./models"):
        self.model_dir = Path(model_dir)
        self.model = None
        self.feature_names = None
        self.metadata = None
        self._load_model()
    
    def _load_model(self):
        """Load the trained model and metadata."""
        try:
            # Load model
            model_path = self.model_dir / "banking_trojan_detector.joblib"
            if not model_path.exists():
                model_path = self.model_dir / "apkshield_model.joblib"
            
            if model_path.exists():
                self.model = joblib.load(model_path)
                print(f"✓ Model loaded from: {model_path}")
            else:
                raise FileNotFoundError("No trained model found")
            
            # Load feature names
            feature_names_path = self.model_dir / "feature_names.csv"
            if feature_names_path.exists():
                self.feature_names = pd.read_csv(feature_names_path)['feature'].tolist()
            else:
                # Default feature names for synthetic model
                self.feature_names = [
                    'total_permissions', 'sensitive_api_count', 'obfuscation_score',
                    'exported_components', 'has_native_code', 'pkg_has_bank_keyword',
                    'sensitive_api_runtime', 'suspicious_syscalls', 'suspicious_domain_hits',
                    'malicious_behavior_score'
                ]
            
            # Load metadata if available
            metadata_path = self.model_dir / "model_metadata.json"
            if metadata_path.exists():
                with open(metadata_path, 'r') as f:
                    self.metadata = json.load(f)
                print(f"✓ Model metadata loaded")
            
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            sys.exit(1)
    
    def extract_features(self, apk_path: str) -> Optional[Dict]:
        """Extract features from an APK file."""
        try:
            # Extract static features
            static_features = extract_static_features(apk_path)
            if not static_features:
                return None
            
            # Create mock dynamic features (in real scenario, use actual traces)
            dynamic_features = create_mock_dynamic_features(static_features['sha256'])
            
            # Combine features
            combined_features = {**static_features, **dynamic_features}
            
            return combined_features
            
        except Exception as e:
            print(f"❌ Error extracting features: {e}")
            return None
    
    def predict(self, features: Dict) -> Dict:
        """Make prediction on extracted features."""
        try:
            # Create DataFrame with required features
            feature_dict = {name: features.get(name, 0) for name in self.feature_names}
            df = pd.DataFrame([feature_dict])
            
            # Make prediction
            prediction = self.model.predict(df)[0]
            probability = self.model.predict_proba(df)[0, 1]
            
            # Determine risk level
            if probability >= 0.8:
                risk_level = "HIGH"
                color = "🔴"
            elif probability >= 0.5:
                risk_level = "MEDIUM"
                color = "🟡"
            else:
                risk_level = "LOW"
                color = "🟢"
            
            return {
                'prediction': int(prediction),
                'probability': float(probability),
                'risk_level': risk_level,
                'color': color,
                'label': "MALWARE" if prediction == 1 else "BENIGN"
            }
            
        except Exception as e:
            print(f"❌ Error making prediction: {e}")
            return None
    
    def scan_apk(self, apk_path: str, verbose: bool = False) -> Dict:
        """Scan a single APK file."""
        apk_file = Path(apk_path)
        
        if not apk_file.exists():
            return {'error': f"File not found: {apk_path}"}
        
        if not apk_file.suffix.lower() == '.apk':
            return {'error': f"Not an APK file: {apk_path}"}
        
        print(f"🔍 Scanning: {apk_file.name}")
        
        # Extract features
        features = self.extract_features(str(apk_file))
        if not features:
            return {'error': "Failed to extract features"}
        
        # Make prediction
        result = self.predict(features)
        if not result:
            return {'error': "Failed to make prediction"}
        
        # Prepare output
        scan_result = {
            'file': apk_file.name,
            'path': str(apk_file),
            'size_mb': round(apk_file.stat().st_size / (1024*1024), 2),
            'package_name': features.get('package_name', 'Unknown'),
            **result
        }
        
        if verbose:
            scan_result['features'] = features
        
        return scan_result
    
    def print_result(self, result: Dict, detailed: bool = False):
        """Print scan results in a formatted way."""
        if 'error' in result:
            print(f"❌ Error: {result['error']}")
            return
        
        print(f"\n{'='*60}")
        print(f"📱 APK SCAN RESULTS")
        print(f"{'='*60}")
        print(f"File: {result['file']}")
        print(f"Size: {result['size_mb']} MB")
        print(f"Package: {result['package_name']}")
        print(f"")
        print(f"🎯 DETECTION RESULT:")
        print(f"   Status: {result['color']} {result['label']}")
        print(f"   Risk Level: {result['risk_level']}")
        print(f"   Confidence: {result['probability']:.1%}")
        
        if detailed and 'features' in result:
            print(f"\n📊 KEY FEATURES:")
            features = result['features']
            key_features = [
                ('Total Permissions', features.get('total_permissions', 0)),
                ('Sensitive APIs', features.get('sensitive_api_count', 0)),
                ('Obfuscation Score', features.get('obfuscation_score', 0)),
                ('Exported Components', features.get('exported_components', 0)),
                ('Has Native Code', 'Yes' if features.get('has_native_code', 0) else 'No'),
                ('Banking Keywords', 'Yes' if features.get('pkg_has_bank_keyword', 0) else 'No'),
                ('Malicious Behavior Score', f"{features.get('malicious_behavior_score', 0):.1f}")
            ]
            
            for feature_name, value in key_features:
                print(f"   {feature_name}: {value}")
        
        print(f"{'='*60}")
        
        # Recommendations
        if result['prediction'] == 1:
            print(f"⚠️  SECURITY RECOMMENDATIONS:")
            print(f"   • Do not install this APK")
            print(f"   • Report to security team if found on devices")
            print(f"   • Consider additional analysis if needed")
        else:
            print(f"✅ This APK appears to be legitimate")
            print(f"   • Low risk of malicious behavior")
            print(f"   • Safe to proceed with normal security practices")
        
        print(f"{'='*60}\n")

def main():
    """Main CLI interface."""
    parser = argparse.ArgumentParser(
        description="APK Banking Trojan Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scan_apk.py sample.apk
  python scan_apk.py sample.apk --detailed
  python scan_apk.py sample.apk --json
  python scan_apk.py *.apk --batch
        """
    )
    
    parser.add_argument('apk_files', nargs='+', help='APK file(s) to scan')
    parser.add_argument('--detailed', '-d', action='store_true', 
                       help='Show detailed feature analysis')
    parser.add_argument('--json', '-j', action='store_true',
                       help='Output results in JSON format')
    parser.add_argument('--batch', '-b', action='store_true',
                       help='Batch mode for multiple files')
    parser.add_argument('--model-dir', '-m', default='./models',
                       help='Directory containing the trained model')
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = APKScanner(args.model_dir)
    
    results = []
    
    # Process each APK file
    for apk_path in args.apk_files:
        apk_file = Path(apk_path)
        
        if apk_file.is_file():
            result = scanner.scan_apk(str(apk_file), verbose=args.detailed)
            results.append(result)
            
            if not args.json and not args.batch:
                scanner.print_result(result, args.detailed)
        else:
            print(f"❌ File not found: {apk_path}")
    
    # Output results
    if args.json:
        if len(results) == 1:
            print(json.dumps(results[0], indent=2))
        else:
            print(json.dumps(results, indent=2))
    elif args.batch and len(results) > 1:
        print(f"\n📊 BATCH SCAN SUMMARY")
        print(f"{'='*50}")
        print(f"Total files scanned: {len(results)}")
        
        malware_count = sum(1 for r in results if r.get('prediction') == 1)
        benign_count = len(results) - malware_count
        
        print(f"🔴 Malware detected: {malware_count}")
        print(f"🟢 Benign files: {benign_count}")
        print(f"{'='*50}")
        
        for result in results:
            if 'error' not in result:
                status = result['color'] + " " + result['label']
                print(f"{result['file']:<30} {status:<15} ({result['probability']:.1%})")

if __name__ == "__main__":
    main()
