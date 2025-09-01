"""
Static Feature Extractor for Android APK Banking Trojan Detection
Extracts static features from APK files including permissions, APIs, certificates, and obfuscation indicators.
"""

import json
import re
import zipfile
import hashlib
import os
import math
from typing import Dict, Optional, List
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis
from rapidfuzz import fuzz
import tldextract

# Dangerous APIs commonly used by banking trojans
DANGEROUS_APIS = [
    'getDeviceId', 'getSubscriberId', 'getLine1Number', 'getAccounts',
    'getInstalledPackages', 'exec', 'loadUrl', 'addJavascriptInterface',
    'sendTextMessage', 'getRunningTasks', 'query', 'getString', 'doFinal',
    'Cipher.getInstance', 'MessageDigest.getInstance', 'SecureRandom',
    'DexClassLoader', 'PathClassLoader', 'System.loadLibrary', 'Runtime.getRuntime',
    'AccessibilityService', 'setAccessibilityServiceInfo', 'getSystemService',
    'startActivity', 'bindService', 'registerReceiver', 'createFromPdu'
]

# Banking-related keywords for package name analysis
BANK_KEYWORDS = [
    "sbi", "icici", "hdfc", "axis", "kotak", "paytm", "phonepe", "gpay", 
    "upi", "bank", "finance", "wallet", "payment", "money", "cash", "pay"
]

# Dangerous permissions commonly requested by banking trojans
DANGEROUS_PERMISSIONS = [
    'READ_SMS', 'SEND_SMS', 'RECEIVE_SMS', 'READ_CONTACTS', 'WRITE_SETTINGS',
    'RECORD_AUDIO', 'USE_SIP', 'SYSTEM_ALERT_WINDOW', 'REQUEST_INSTALL_PACKAGES',
    'BIND_ACCESSIBILITY_SERVICE', 'READ_PHONE_STATE', 'READ_CALL_LOG',
    'WRITE_SECURE_SETTINGS', 'ANSWER_PHONE_CALLS', 'CALL_PHONE',
    'WRITE_EXTERNAL_STORAGE', 'READ_EXTERNAL_STORAGE', 'CAMERA',
    'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'GET_ACCOUNTS',
    'MANAGE_ACCOUNTS', 'AUTHENTICATE_ACCOUNTS', 'USE_CREDENTIALS'
]

def sha256_hash(file_path: str) -> str:
    """Calculate SHA256 hash of a file."""
    hash_obj = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024*1024), b''):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()

def check_individual_permissions(permissions: List[str]) -> Dict:
    """Check for specific individual permissions."""
    features = {}
    
    # Check for critical permissions
    features['has_system_alert_window'] = 1 if any('SYSTEM_ALERT_WINDOW' in p for p in permissions) else 0
    features['has_bind_accessibility_service'] = 1 if any('BIND_ACCESSIBILITY_SERVICE' in p for p in permissions) else 0
    features['has_bind_device_admin'] = 1 if any('BIND_DEVICE_ADMIN' in p for p in permissions) else 0
    features['has_read_sms'] = 1 if any('READ_SMS' in p for p in permissions) else 0
    features['has_send_sms'] = 1 if any('SEND_SMS' in p for p in permissions) else 0
    features['has_receive_sms'] = 1 if any('RECEIVE_SMS' in p for p in permissions) else 0
    features['has_read_phone_state'] = 1 if any('READ_PHONE_STATE' in p for p in permissions) else 0
    features['has_call_phone'] = 1 if any('CALL_PHONE' in p for p in permissions) else 0
    features['has_record_audio'] = 1 if any('RECORD_AUDIO' in p for p in permissions) else 0
    features['has_camera'] = 1 if any('CAMERA' in p for p in permissions) else 0
    features['has_access_fine_location'] = 1 if any('ACCESS_FINE_LOCATION' in p for p in permissions) else 0
    features['has_write_settings'] = 1 if any('WRITE_SETTINGS' in p for p in permissions) else 0
    features['has_install_packages'] = 1 if any('INSTALL_PACKAGES' in p for p in permissions) else 0
    features['has_delete_packages'] = 1 if any('DELETE_PACKAGES' in p for p in permissions) else 0
    features['has_write_external_storage'] = 1 if any('WRITE_EXTERNAL_STORAGE' in p for p in permissions) else 0
    
    return features

def is_dangerous_permission(permission: str) -> bool:
    """Check if a permission is considered dangerous"""
    dangerous_keywords = [
        'READ_SMS', 'SEND_SMS', 'RECEIVE_SMS', 'READ_CONTACTS', 'WRITE_SETTINGS',
        'RECORD_AUDIO', 'SYSTEM_ALERT_WINDOW', 'INSTALL_PACKAGES', 'DELETE_PACKAGES',
        'BIND_ACCESSIBILITY_SERVICE', 'READ_PHONE_STATE', 'CALL_PHONE', 'CAMERA',
        'ACCESS_FINE_LOCATION', 'WRITE_EXTERNAL_STORAGE', 'GET_ACCOUNTS'
    ]
    return any(keyword in permission for keyword in dangerous_keywords)

def calculate_hash(file_path: str) -> str:
    """Calculate SHA256 hash of file"""
    return sha256_hash(file_path)

def extract_static_features(apk_path: str) -> Optional[Dict]:
    """Extract static features from APK file with API level compatibility fixes"""
    try:
        print(f"Extracting static features from: {apk_path}")
        
        # Load APK with skip_analysis to avoid immediate DEX parsing
        apk = APK(apk_path, skip_analysis=True)
        
        features = {}
        
        # Basic APK info
        features['sha256'] = calculate_hash(apk_path)
        features['file_size_mb'] = round(os.path.getsize(apk_path) / (1024 * 1024), 2)
        features['package_name'] = apk.get_package() or 'unknown'
        features['app_name'] = apk.get_app_name() or 'unknown'
        features['version_name'] = apk.get_androidversion_name() or '1.0'
        features['version_code'] = apk.get_androidversion_code() or 1
        
        # API levels with compatibility fixes
        min_sdk = apk.get_min_sdk_version()
        target_sdk = apk.get_target_sdk_version()
        
        # Cap SDK versions to 28 for Androguard compatibility
        features['min_sdk'] = min(min_sdk, 28) if min_sdk else 1
        features['target_sdk'] = min(target_sdk, 28) if target_sdk else 28
        features['original_target_sdk'] = target_sdk  # Keep original for reference
        
        print(f"Target SDK {target_sdk} capped to {features['target_sdk']} for Androguard compatibility")
        
        # Permissions
        permissions = apk.get_permissions() or []
        features['total_permissions'] = len(permissions)
        
        dangerous_perms = [p for p in permissions if is_dangerous_permission(p)]
        features['dangerous_permissions'] = len(dangerous_perms)
        features['permission_ratio'] = len(dangerous_perms) / max(len(permissions), 1)
        
        # Individual permission checks
        features.update(check_individual_permissions(permissions))
        
        # Component counts
        features['activities_count'] = len(apk.get_activities() or [])
        features['services_count'] = len(apk.get_services() or [])
        features['receivers_count'] = len(apk.get_receivers() or [])
        
    except Exception as e:
        print(f"Basic feature extraction failed: {e}")
        return None
    
    # Security flags
    features['is_debuggable'] = 1 if apk.is_debuggable() else 0
    features['allows_backup'] = 1 if apk.get_element('application', 'allowBackup') == 'true' else 0
    
    # Exported components (security risk)
    exported_count = 0
    try:
        for activity in (apk.get_activities() or []):
            if apk.get_element('activity', activity).get('exported') == 'true':
                exported_count += 1
        for service in (apk.get_services() or []):
            if apk.get_element('service', service).get('exported') == 'true':
                exported_count += 1
        for receiver in (apk.get_receivers() or []):
            if apk.get_element('receiver', receiver).get('exported') == 'true':
                exported_count += 1
    except:
        pass
    features['exported_components'] = exported_count
    
    # Code analysis
    sensitive_api_count = 0
    url_count = 0
    has_native_code = 0
    obfuscation_score = 0
    reflection_count = 0
    crypto_usage = 0
    
    try:
        with zipfile.ZipFile(apk_path) as zip_file:
            # Check for native libraries
            for file_name in zip_file.namelist():
                if file_name.endswith('.so'):
                    has_native_code = 1
                    
                # Extract URLs from resources
                if file_name.endswith(('.txt', '.xml', '.json', '.html', '.js', '.properties')):
                    try:
                        content = zip_file.read(file_name).decode('utf-8', 'ignore')
                        urls = re.findall(r'https?://[^\s\'"<>]+', content)
                        url_count += len(urls)
                    except:
                        pass
            
            # Analyze DEX files
            dex_files = [zip_file.read(name) for name in zip_file.namelist() if name.endswith('.dex')]
            
        for dex_data in dex_files:
            try:
                # Use safe DEX parsing with error handling
                dvm = DalvikVMFormat(dex_data, using_api=28)  # Force API 28 compatibility
                
                # Skip full analysis if it causes issues, use basic parsing
                try:
                    analysis = Analysis(dvm)
                    dvm.set_vmanalysis(analysis)
                    use_analysis = True
                except Exception as analysis_error:
                    print(f"Analysis failed, using basic DEX parsing: {analysis_error}")
                    use_analysis = False
                
                # Extract method information safely
                try:
                    methods = dvm.get_methods() if use_analysis else []
                    for method in methods:
                        try:
                            method_name = str(method.get_name())
                            
                            # Obfuscation detection: short method names
                            if len(method_name) <= 2 and method_name.isalpha():
                                obfuscation_score += 1
                            
                            # Sensitive API usage
                            for api in DANGEROUS_APIS:
                                if api in method_name:
                                    sensitive_api_count += 1
                            
                            # Reflection usage
                            if any(ref in method_name for ref in ['reflect', 'invoke', 'getMethod', 'getClass']):
                                reflection_count += 1
                            
                            # Crypto usage
                            if any(crypto in method_name for crypto in ['cipher', 'encrypt', 'decrypt', 'hash']):
                                crypto_usage += 1
                        except Exception as method_error:
                            continue
                            
                except Exception as methods_error:
                    print(f"Method extraction failed: {methods_error}")
                    
            except Exception as dex_error:
                print(f"DEX parsing failed: {dex_error}")
                continue
                
    except Exception as e:
        print(f"Error analyzing code in {apk_path}: {e}")
    
    features['sensitive_api_count'] = sensitive_api_count
    features['url_count'] = url_count
    features['has_native_code'] = has_native_code
    features['obfuscation_score'] = min(obfuscation_score, 1000)  # Cap to prevent outliers
    features['reflection_count'] = reflection_count
    features['crypto_usage'] = crypto_usage
    
    # Banking-related heuristics
    package_lower = features['package_name'].lower()
    app_name_lower = features['app_name'].lower()
    
    features['pkg_has_bank_keyword'] = 1 if any(kw in package_lower for kw in BANK_KEYWORDS) else 0
    features['app_has_bank_keyword'] = 1 if any(kw in app_name_lower for kw in BANK_KEYWORDS) else 0
    features['name_pkg_similarity'] = fuzz.partial_ratio(app_name_lower, package_lower)
    
    # Certificate analysis
    try:
        certs = (apk.get_certificates_der_v2() or 
                apk.get_certificates_der_v3() or 
                apk.get_certificates_der_v1())
        features['certificate_count'] = len(certs) if certs else 0
    except:
        features['certificate_count'] = 0
    
    # Intent filter analysis
    intent_filter_count = 0
    try:
        for activity in (apk.get_activities() or []):
            activity_elem = apk.get_element('activity', activity)
            if activity_elem and activity_elem.findall('.//intent-filter'):
                intent_filter_count += len(activity_elem.findall('.//intent-filter'))
    except:
        pass
    features['intent_filter_count'] = intent_filter_count
    
    return features

def extract_features_batch(apk_directory: str, label: int) -> List[Dict]:
    """
    Extract features from all APK files in a directory.
    
    Args:
        apk_directory: Directory containing APK files
        label: Label for the APKs (0 for benign, 1 for malware)
        
    Returns:
        List of feature dictionaries
    """
    features_list = []
    
    if not os.path.exists(apk_directory):
        print(f"Directory {apk_directory} does not exist")
        return features_list
    
    apk_files = [f for f in os.listdir(apk_directory) if f.endswith('.apk')]
    print(f"Processing {len(apk_files)} APK files from {apk_directory}")
    
    for apk_file in apk_files:
        apk_path = os.path.join(apk_directory, apk_file)
        print(f"Processing: {apk_file}")
        
        features = extract_static_features(apk_path)
        if features:
            features['label'] = label
            features['filename'] = apk_file
            features_list.append(features)
        else:
            print(f"Failed to extract features from {apk_file}")
    
    return features_list

if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python static_feature_extractor.py <apk_file>")
        sys.exit(1)
    
    apk_path = sys.argv[1]
    features = extract_static_features(apk_path)
    
    if features:
        print(json.dumps(features, indent=2))
    else:
        print("Failed to extract features")
