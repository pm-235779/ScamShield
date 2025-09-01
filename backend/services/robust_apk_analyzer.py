"""
Robust APK Analyzer with API Level Compatibility
Handles newer API levels and provides fallback mechanisms for ML feature extraction.
"""

import os
import warnings
from typing import Dict, Any, Optional
from androguard.core.bytecodes import apk
import hashlib

class RobustAPKAnalyzer:
    """Enhanced APK analyzer with API level compatibility and robust error handling"""
    
    def __init__(self):
        # Suppress Androguard warnings
        warnings.filterwarnings("ignore")
        
    def safe_extract_features(self, apk_path: str) -> Optional[Dict[str, Any]]:
        """
        Safely extract features with multiple fallback strategies for API level issues
        """
        try:
            # Strategy 1: Try ML feature extractor with API level fixes
            return self._try_ml_extraction(apk_path)
        except Exception as e:
            print(f"ML extraction failed: {e}")
            try:
                # Strategy 2: Basic feature extraction with compatibility mode
                return self._try_basic_extraction(apk_path)
            except Exception as e2:
                print(f"Basic extraction failed: {e2}")
                # Strategy 3: Minimal safe extraction
                return self._minimal_safe_extraction(apk_path)
    
    def _try_ml_extraction(self, apk_path: str) -> Optional[Dict[str, Any]]:
        """Try ML feature extraction with API level compatibility"""
        import sys
        ml_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'ml')
        if ml_path not in sys.path:
            sys.path.append(ml_path)
        
        from static_feature_extractor import extract_static_features
        features = extract_static_features(apk_path)
        
        if features:
            print("✅ ML feature extraction successful")
            return features
        else:
            raise Exception("ML feature extraction returned None")
    
    def _try_basic_extraction(self, apk_path: str) -> Dict[str, Any]:
        """Basic feature extraction with API level compatibility"""
        # Load APK with skip_analysis to avoid DEX parsing issues
        a = apk.APK(apk_path, skip_analysis=True)
        
        features = {}
        
        # Basic file info
        features['sha256'] = self._calculate_hash(apk_path)
        features['size_mb'] = round(os.path.getsize(apk_path) / (1024*1024), 2)
        
        # Package info with safe extraction
        try:
            features['package_name'] = a.get_package() or "com.unknown.app"
        except:
            features['package_name'] = "com.unknown.app"
        
        try:
            features['app_name'] = a.get_app_name() or "Unknown App"
        except:
            features['app_name'] = "Unknown App"
        
        # Version info with error handling
        try:
            features['version_name'] = a.get_androidversion_name() or "1.0"
        except:
            features['version_name'] = "1.0"
        
        try:
            features['version_code'] = a.get_androidversion_code() or 1
        except:
            features['version_code'] = 1
        
        # SDK versions with API level capping
        try:
            min_sdk = a.get_min_sdk_version() or 1
            target_sdk = a.get_target_sdk_version() or 28
            
            # Cap to API 28 for compatibility
            features['min_sdk'] = min(int(min_sdk), 28) if min_sdk else 1
            features['target_sdk'] = min(int(target_sdk), 28) if target_sdk else 28
            features['original_target_sdk'] = int(target_sdk) if target_sdk else 28
            
            if int(target_sdk) > 28:
                print(f"Target SDK {target_sdk} capped to 28 for Androguard compatibility")
                
        except Exception as e:
            print(f"SDK extraction error: {e}")
            features['min_sdk'] = 1
            features['target_sdk'] = 28
            features['original_target_sdk'] = 28
        
        # Permissions with safe extraction
        try:
            permissions = a.get_permissions() or []
            print(f"📋 Found {len(permissions)} total permissions")
            
            # If no permissions found, try alternative extraction
            if not permissions:
                try:
                    # Try to get permissions from manifest directly
                    manifest = a.get_android_manifest_xml()
                    if manifest:
                        import xml.etree.ElementTree as ET
                        root = ET.fromstring(manifest)
                        perm_elements = root.findall('.//{http://schemas.android.com/apk/res/android}uses-permission')
                        permissions = [elem.get('{http://schemas.android.com/apk/res/android}name', '') for elem in perm_elements if elem.get('{http://schemas.android.com/apk/res/android}name')]
                        print(f"📋 Extracted {len(permissions)} permissions from manifest XML")
                except Exception as xml_e:
                    print(f"XML manifest extraction failed: {xml_e}")
            
            features['total_permissions'] = len(permissions)
            
            if permissions:
                print(f"Sample permissions: {permissions[:3]}")
            
            # Count dangerous permissions with better matching and NaN protection
            dangerous_perms = []
            for perm in permissions:
                # Extract permission name after last dot for better matching
                perm_name = perm.split('.')[-1] if '.' in perm else perm
                for dangerous in DANGEROUS_PERMISSIONS:
                    dangerous_name = dangerous.split('.')[-1] if '.' in dangerous else dangerous
                    # Bidirectional matching
                    if dangerous_name.lower() in perm_name.lower() or perm_name.lower() in dangerous_name.lower():
                        if perm not in dangerous_perms:
                            dangerous_perms.append(perm)
                        break
            
            features['dangerous_permissions'] = max(0, len(dangerous_perms))
            features['dangerous_permissions_list'] = dangerous_perms
            
            # Safe permission ratio calculation
            if len(permissions) > 0:
                features['permission_ratio'] = min(1.0, len(dangerous_perms) / len(permissions))
            else:
                features['permission_ratio'] = 0.0
            
            print(f"🚨 Found {len(dangerous_perms)} dangerous permissions: {dangerous_perms[:3]}")
            
            # Individual permission flags for ML with NaN protection
            permission_checks = [
                ('has_system_alert_window', 'SYSTEM_ALERT_WINDOW'),
                ('has_bind_accessibility_service', 'BIND_ACCESSIBILITY_SERVICE'),
                ('has_bind_device_admin', 'BIND_DEVICE_ADMIN'),
                ('has_read_sms', 'READ_SMS'),
                ('has_send_sms', 'SEND_SMS'),
                ('has_receive_sms', 'RECEIVE_SMS'),
                ('has_camera', 'CAMERA'),
                ('has_record_audio', 'RECORD_AUDIO')
            ]
            
            for flag_name, perm_keyword in permission_checks:
                has_permission = any(perm_keyword in p for p in permissions)
                features[flag_name] = int(bool(has_permission))
            
            features['permissions'] = permissions
        except Exception as e:
            print(f"Permission extraction error: {e}")
            features['total_permissions'] = 0
            features['dangerous_permissions'] = 0
            features['permission_ratio'] = 0.0
        
        # Component counts with safe extraction
        try:
            features['activities_count'] = len(a.get_activities() or [])
            features['services_count'] = len(a.get_services() or [])
            features['receivers_count'] = len(a.get_receivers() or [])
        except:
            features['activities_count'] = 0
            features['services_count'] = 0
            features['receivers_count'] = 0
        
        # Certificate analysis
        features.update(self._safe_certificate_analysis(a))
        
        # Standardize features for ML model compatibility
        from .feature_standardizer import standardize_apk_features
        standardized_features = standardize_apk_features(features)
        
        # Keep original features for rule-based analysis, use standardized for ML
        features['ml_features'] = standardized_features
        
        print(f"✅ Basic feature extraction successful: {len(features)} features")
        return features
    
    def _minimal_safe_extraction(self, apk_path: str) -> Dict[str, Any]:
        """Minimal safe feature extraction when all else fails"""
        print("⚠️ Using minimal safe extraction")
        
        features = {
            'sha256': self._calculate_hash(apk_path),
            'size_mb': round(os.path.getsize(apk_path) / (1024*1024), 2),
            'package_name': 'com.unknown.app',
            'app_name': 'Unknown App',
            'version_name': '1.0',
            'version_code': 1,
            'min_sdk': 1,
            'target_sdk': 28,
            'original_target_sdk': 28,
            'total_permissions': 0,
            'dangerous_permissions': 0,
            'permission_ratio': 0.0,
            'activities_count': 0,
            'services_count': 0,
            'receivers_count': 0,
            'is_self_signed': 1,
            'cert_valid': 0,
            'suspicious_strings_count': 0,
            'has_ip_address': 0,
            'has_banking_keywords': 0,
            'file_size_mb': round(os.path.getsize(apk_path) / (1024*1024), 2)
        }
        
        # Add permission flags
        dangerous_perms = [
            'SYSTEM_ALERT_WINDOW', 'BIND_ACCESSIBILITY_SERVICE', 'BIND_DEVICE_ADMIN',
            'READ_SMS', 'SEND_SMS', 'RECEIVE_SMS', 'READ_PHONE_STATE', 'CALL_PHONE',
            'RECORD_AUDIO', 'CAMERA', 'ACCESS_FINE_LOCATION', 'WRITE_SETTINGS',
            'INSTALL_PACKAGES', 'DELETE_PACKAGES', 'WRITE_EXTERNAL_STORAGE'
        ]
        
        for perm in dangerous_perms:
            features[f'has_{perm.lower()}'] = 0
        
        # Add mock dynamic features
        features.update(self._create_mock_dynamic_features())
        
        return features
    
    def _safe_certificate_analysis(self, a: apk.APK) -> Dict[str, Any]:
        """Safe certificate analysis with error handling"""
        try:
            signature_names = a.get_signature_names()
            if signature_names:
                cert_der = a.get_certificate_der(signature_names[0])
                if cert_der:
                    try:
                        from cryptography import x509
                        from cryptography.hazmat.backends import default_backend
                        from datetime import datetime, timezone
                        
                        cert = x509.load_der_x509_certificate(cert_der, default_backend())
                        is_self_signed = cert.issuer == cert.subject
                        
                        # Handle timezone-aware datetime comparison
                        now = datetime.now(timezone.utc)
                        not_before = cert.not_valid_before
                        not_after = cert.not_valid_after
                        
                        if not_before.tzinfo is None:
                            not_before = not_before.replace(tzinfo=timezone.utc)
                        if not_after.tzinfo is None:
                            not_after = not_after.replace(tzinfo=timezone.utc)
                        
                        is_valid = not_before <= now <= not_after
                        
                        return {
                            'is_self_signed': int(is_self_signed),
                            'cert_valid': int(is_valid)
                        }
                    except Exception as cert_error:
                        print(f"Certificate parsing error: {cert_error}")
                        pass
            
            return {'is_self_signed': 1, 'cert_valid': 0}
            
        except Exception as e:
            print(f"Certificate analysis error: {e}")
            return {'is_self_signed': 1, 'cert_valid': 0}
    
    def _add_required_model_features(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Add all features required by the trained model"""
        required_features = {
            # Core features the model expects
            'file_size_mb': features.get('size_mb', 0),
            'has_banking_keywords': 0,
            'has_ip_address': 0,
            'suspicious_strings_count': 0,
            
            # Dynamic features (mock values based on static analysis)
            'sensitive_api_runtime': features.get('dangerous_permissions', 0) * 2,
            'suspicious_syscalls': min(features.get('dangerous_permissions', 0) * 3, 50),
            'suspicious_domain_hits': 0,
            'malicious_behavior_score': (
                features.get('dangerous_permissions', 0) * 2 +
                features.get('is_self_signed', 0) * 10 +
                (1 - features.get('cert_valid', 1)) * 15
            )
        }
        
        # Remove features that the model doesn't expect
        unwanted_features = [
            'sha256', 'size_mb', 'package_name', 'app_name', 'version_name', 'version_code',
            'original_target_sdk', 'sample_id', 'unique_domains', 'total_bytes_out', 
            'total_bytes_in', 'avg_bytes_per_conn', 'suspicious_ip_hits', 'unique_dst_ips',
            'unique_src_ports', 'http_connections', 'https_connections', 'dns_queries',
            'tcp_connections', 'udp_connections', 'connection_duration_avg', 'total_api_calls',
            'unique_apis', 'reflection_calls', 'crypto_calls', 'file_operations',
            'network_operations', 'sms_operations', 'contact_operations', 'location_operations',
            'camera_operations', 'microphone_operations', 'total_syscalls', 'unique_syscalls',
            'file_syscalls', 'network_syscalls', 'process_syscalls', 'memory_syscalls',
            'ipc_syscalls', 'total_dynamic_activity'
        ]
        
        return required_features
    
    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        hash_obj = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(1024*1024), b''):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except:
            return "unknown_hash"

def extract_features_with_fallback(apk_path: str) -> Dict[str, Any]:
    """
    Main function to extract features with comprehensive fallback handling
    """
    analyzer = RobustAPKAnalyzer()
    features = analyzer.safe_extract_features(apk_path)
    
    if features is None:
        print("⚠️ All extraction methods failed, using minimal defaults")
        features = {
            'total_permissions': 0,
            'dangerous_permissions': 0,
            'permission_ratio': 0.0,
            'is_self_signed': 1,
            'cert_valid': 0,
            'file_size_mb': 0,
            'target_sdk': 28,
            'min_sdk': 1
        }
    
    return features
