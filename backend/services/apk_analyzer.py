import os
import re
import sys
from typing import Dict, List, Any
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
import hashlib

# Add ML folder to path for importing feature extractors
ml_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'ml')
if ml_path not in sys.path:
    sys.path.append(ml_path)

try:
    from static_feature_extractor import extract_static_features, DANGEROUS_PERMISSIONS as ML_DANGEROUS_PERMISSIONS
    from dynamic_feature_extractor import create_mock_dynamic_features
    ML_AVAILABLE = True
except ImportError as e:
    print(f"Warning: ML feature extractors not available: {e}")
    ML_AVAILABLE = False

class APKAnalyzer:
    """APK static analysis using Androguard"""
    
    def __init__(self):
        self.dangerous_permissions = {
            'SYSTEM_ALERT_WINDOW', 'BIND_ACCESSIBILITY_SERVICE', 'WRITE_EXTERNAL_STORAGE',
            'READ_SMS', 'SEND_SMS', 'RECEIVE_SMS', 'READ_PHONE_STATE', 'CALL_PHONE',
            'RECORD_AUDIO', 'CAMERA', 'ACCESS_FINE_LOCATION', 'WRITE_SETTINGS',
            'INSTALL_PACKAGES', 'DELETE_PACKAGES', 'BIND_DEVICE_ADMIN'
        }
        
        self.suspicious_patterns = [
            r'http://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',  # IP addresses
            r'\.onion',  # Tor domains
            r'bitcoin|btc|wallet',  # Crypto related
            r'overlay|accessibility|admin',  # Malicious services
            r'sms|bank|pay|card|pin',  # Banking keywords
        ]

    def analyze(self, apk_path: str) -> Dict[str, Any]:
        """Perform comprehensive APK analysis"""
        try:
            # Load APK with error handling for API level issues
            import warnings
            warnings.filterwarnings("ignore")
            a = apk.APK(apk_path, skip_analysis=True)
            
            # Basic app info with better extraction
            app_info = {}
            
            # Get app name with fallback to package name
            try:
                app_name = a.get_app_name()
                if not app_name or app_name.strip() == '':
                    # Try to get from manifest
                    manifest = a.get_android_manifest_xml()
                    if manifest and 'application' in str(manifest):
                        import xml.etree.ElementTree as ET
                        try:
                            root = ET.fromstring(manifest)
                            app_label = root.find('.//{http://schemas.android.com/apk/res/android}application')
                            if app_label is not None:
                                label = app_label.get('{http://schemas.android.com/apk/res/android}label')
                                if label and not label.startswith('@'):
                                    app_name = label
                        except:
                            pass
                    
                    # Final fallback to package name
                    if not app_name:
                        package = a.get_package()
                        if package:
                            app_name = package.split('.')[-1].title()
                        else:
                            app_name = 'Unknown App'
                
                app_info['app_name'] = app_name
            except Exception as e:
                print(f"Error getting app name: {e}")
                app_info['app_name'] = 'Unknown App'
            
            # Get package name
            try:
                package_name = a.get_package()
                app_info['package_name'] = package_name if package_name else 'com.unknown.app'
            except Exception as e:
                print(f"Error getting package name: {e}")
                app_info['package_name'] = 'com.unknown.app'
            
            # Get version info
            try:
                version_name = a.get_androidversion_name()
                app_info['version_name'] = version_name if version_name else '1.0'
            except Exception as e:
                print(f"Error getting version name: {e}")
                app_info['version_name'] = '1.0'
            
            try:
                version_code = a.get_androidversion_code()
                app_info['version_code'] = version_code if version_code else 1
            except Exception as e:
                print(f"Error getting version code: {e}")
                app_info['version_code'] = 1
            
            # Get SDK versions with API level compatibility
            try:
                min_sdk = a.get_min_sdk_version()
                original_min_sdk = min_sdk if min_sdk else 1
                # Cap to API 28 for Androguard compatibility
                app_info['min_sdk'] = min(original_min_sdk, 28)
                app_info['original_min_sdk'] = original_min_sdk
            except Exception as e:
                print(f"Error getting min SDK: {e}")
                app_info['min_sdk'] = 1
                app_info['original_min_sdk'] = 1
            
            try:
                target_sdk = a.get_target_sdk_version()
                original_target_sdk = target_sdk if target_sdk else 28
                # Cap to API 28 for Androguard compatibility
                app_info['target_sdk'] = min(original_target_sdk, 28)
                app_info['original_target_sdk'] = original_target_sdk
                
                # Log if we had to cap the API level
                if original_target_sdk > 28:
                    print(f"Target SDK {original_target_sdk} capped to 28 for compatibility")
            except Exception as e:
                print(f"Error getting target SDK: {e}")
                app_info['target_sdk'] = 28
                app_info['original_target_sdk'] = 28
            
            # Permissions analysis with error handling
            try:
                permissions = a.get_permissions() or []
                print(f"Raw permissions found: {len(permissions)}")
                if permissions:
                    print(f"Sample permissions: {permissions[:5]}")
            except Exception as e:
                print(f"Error getting permissions: {e}")
                permissions = []
            
            # More robust dangerous permission detection
            dangerous_perms = []
            for perm in permissions:
                # Extract the permission name after the last dot
                perm_name = perm.split('.')[-1] if '.' in perm else perm
                for dangerous_perm in self.dangerous_permissions:
                    if dangerous_perm.lower() in perm_name.lower() or perm_name.lower() in dangerous_perm.lower():
                        dangerous_perms.append(perm)
                        break
            
            print(f"🔍 Dangerous permissions found: {len(dangerous_perms)}")
            if dangerous_perms:
                print(f"🚨 Dangerous perms: {dangerous_perms[:3]}")
            
            # Debug: Show all permissions for troubleshooting
            if len(permissions) > 0:
                print(f"📋 All permissions: {[p.split('.')[-1] for p in permissions[:5]]}")
            else:
                print("⚠️ No permissions found in APK")
            
            # Certificate analysis
            cert_info = self._analyze_certificate(a)
            
            # String analysis for suspicious content
            suspicious_strings = self._find_suspicious_strings(a)
            
            # Activities and services with error handling
            try:
                activities = a.get_activities() or []
            except:
                activities = []
            
            try:
                services = a.get_services() or []
            except:
                services = []
            
            try:
                receivers = a.get_receivers() or []
            except:
                receivers = []
            
            # Additional app metadata
            additional_info = self._extract_additional_info(a, apk_path)
            
            return {
                **app_info,
                **additional_info,
                'permissions': permissions,
                'dangerous_permissions': dangerous_perms,
                'certificate_info': cert_info,
                'suspicious_strings': suspicious_strings,
                'activities': activities,
                'services': services,
                'receivers': receivers,
                'file_size': os.path.getsize(apk_path),
                'apk_path': apk_path  # Include path for ML feature extraction
            }
            
        except Exception as e:
            raise Exception(f"APK analysis failed: {str(e)}")

    def extract_features(self, apk_info: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features for ML model using enhanced ML extractors when available"""
        features = {}
        
        # If ML extractors are available and we have the APK path, use them for comprehensive features
        if ML_AVAILABLE and 'apk_path' in apk_info:
            try:
                # Use robust feature extraction with API level compatibility
                from .robust_apk_analyzer import extract_features_with_fallback
                ml_features = extract_features_with_fallback(apk_info['apk_path'])
                
                if ml_features:
                    # Use ML features as base
                    features.update(ml_features)
                    
                    # Add dynamic features (mock for now)
                    dynamic_features = create_mock_dynamic_features(ml_features.get('sha256', 'unknown'))
                    features.update(dynamic_features)
                    
                    print(f"✅ Enhanced ML features extracted: {len(features)} total features")
                    return features
            except Exception as e:
                print(f"ML feature extraction failed, falling back to basic extraction: {e}")
        
        # Fallback to basic feature extraction
        # Permission-based features
        all_perms = apk_info.get('permissions', [])
        dangerous_perms = apk_info.get('dangerous_permissions', [])
        
        features['total_permissions'] = len(all_perms)
        features['dangerous_permissions'] = len(dangerous_perms)
        features['permission_ratio'] = len(dangerous_perms) / max(len(all_perms), 1)
        
        # One-hot encoding for critical permissions
        for perm in self.dangerous_permissions:
            features[f'has_{perm.lower()}'] = int(any(perm in p for p in all_perms))
        
        # App metadata features
        features['min_sdk'] = apk_info.get('min_sdk', 0)
        features['target_sdk'] = apk_info.get('target_sdk', 0)
        features['version_code'] = apk_info.get('version_code', 0)
        features['file_size_mb'] = apk_info.get('file_size', 0) / (1024 * 1024)
        
        # Certificate features
        cert_info = apk_info.get('certificate_info', {})
        features['is_self_signed'] = int(cert_info.get('is_self_signed', False))
        features['cert_valid'] = int(cert_info.get('is_valid', True))
        
        # Component counts
        features['activities_count'] = len(apk_info.get('activities', []))
        features['services_count'] = len(apk_info.get('services', []))
        features['receivers_count'] = len(apk_info.get('receivers', []))
        
        # Suspicious content features
        suspicious_strings = apk_info.get('suspicious_strings', [])
        features['suspicious_strings_count'] = len(suspicious_strings)
        features['has_ip_address'] = int(any('http://' in s and re.search(r'\d+\.\d+\.\d+\.\d+', s) for s in suspicious_strings))
        features['has_banking_keywords'] = int(any(re.search(r'bank|pay|card|pin', s, re.I) for s in suspicious_strings))
        
        # Add mock dynamic features for consistency
        features['sensitive_api_runtime'] = len(dangerous_perms) * 2  # Mock based on permissions
        features['suspicious_syscalls'] = min(features['suspicious_strings_count'] * 3, 50)
        features['suspicious_domain_hits'] = 1 if features['has_ip_address'] else 0
        features['malicious_behavior_score'] = (
            features['sensitive_api_runtime'] * 2 +
            features['suspicious_syscalls'] * 1.5 +
            features['suspicious_domain_hits'] * 3
        )
        
        return features

    def _analyze_certificate(self, a: apk.APK) -> Dict[str, Any]:
        """Analyze APK certificate"""
        try:
            signature_names = a.get_signature_names()
            if signature_names:
                cert_der = a.get_certificate_der(signature_names[0])
                if cert_der:
                    # Try to get certificate info
                    try:
                        from cryptography import x509
                        from cryptography.hazmat.backends import default_backend
                        
                        cert = x509.load_der_x509_certificate(cert_der, default_backend())
                        
                        # Check if self-signed (simplified check)
                        is_self_signed = cert.issuer == cert.subject
                        
                        # Check validity period with timezone handling
                        from datetime import datetime, timezone
                        now = datetime.now(timezone.utc)
                        
                        # Handle timezone-naive certificates
                        not_before = cert.not_valid_before
                        not_after = cert.not_valid_after
                        
                        if not_before.tzinfo is None:
                            not_before = not_before.replace(tzinfo=timezone.utc)
                        if not_after.tzinfo is None:
                            not_after = not_after.replace(tzinfo=timezone.utc)
                            
                        is_valid = not_before <= now <= not_after
                        
                        # Get signature algorithm
                        sig_algorithm = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else 'Unknown'
                        
                        return {
                            'is_self_signed': is_self_signed,
                            'is_valid': is_valid,
                            'signature_algorithm': sig_algorithm,
                            'issuer': cert.issuer.rfc4514_string(),
                            'subject': cert.subject.rfc4514_string(),
                            'valid_from': cert.not_valid_before.isoformat(),
                            'valid_to': cert.not_valid_after.isoformat()
                        }
                    except ImportError:
                        # Fallback if cryptography is not available
                        print("Cryptography library not available for detailed certificate analysis")
                        pass
                    except Exception as e:
                        print(f"Certificate parsing error: {e}")
                        pass
                
                # Basic fallback analysis
                return {
                    'is_self_signed': True,  # Assume self-signed for unknown certs
                    'is_valid': True,       # Assume valid if we can't check
                    'signature_algorithm': 'SHA1withRSA',
                    'issuer': 'Unknown',
                    'subject': 'Unknown'
                }
        except Exception as e:
            print(f"Certificate analysis error: {e}")
        
        return {
            'is_self_signed': True,
            'is_valid': False,
            'signature_algorithm': 'None',
            'issuer': 'None',
            'subject': 'None'
        }

    def _find_suspicious_strings(self, a: apk.APK) -> List[str]:
        """Find suspicious strings in APK"""
        suspicious = []
        
        try:
            # Get all strings from APK
            all_strings = []
            
            # Extract strings from manifest
            manifest = a.get_android_manifest_xml()
            if manifest:
                all_strings.extend(re.findall(r'[a-zA-Z0-9:/._-]+', str(manifest)))
            
            # Check against suspicious patterns
            for string in all_strings[:1000]:  # Limit to avoid performance issues
                for pattern in self.suspicious_patterns:
                    if re.search(pattern, string, re.I):
                        suspicious.append(string)
                        break
                        
        except Exception as e:
            print(f"String analysis error: {e}")
        
        return list(set(suspicious))[:20]  # Return unique, limited results

    def _extract_additional_info(self, a: apk.APK, apk_path: str) -> Dict[str, Any]:
        """Extract additional app metadata for better display"""
        additional = {}
        
        try:
            # Get install location
            manifest = a.get_android_manifest_xml()
            if manifest:
                import xml.etree.ElementTree as ET
                try:
                    root = ET.fromstring(manifest)
                    # Install location
                    install_location = root.get('{http://schemas.android.com/apk/res/android}installLocation', 'auto')
                    additional['install_location'] = install_location
                    
                    # Get app description/label from manifest
                    app_node = root.find('.//{http://schemas.android.com/apk/res/android}application')
                    if app_node is not None:
                        description = app_node.get('{http://schemas.android.com/apk/res/android}description', '')
                        if description and not description.startswith('@'):
                            additional['description'] = description
                        
                        # Check if app allows backup
                        allow_backup = app_node.get('{http://schemas.android.com/apk/res/android}allowBackup', 'true')
                        additional['allows_backup'] = allow_backup.lower() == 'true'
                        
                        # Check if debuggable
                        debuggable = app_node.get('{http://schemas.android.com/apk/res/android}debuggable', 'false')
                        additional['is_debuggable'] = debuggable.lower() == 'true'
                        
                        # Check icon
                        icon = app_node.get('{http://schemas.android.com/apk/res/android}icon', '')
                        if icon:
                            additional['icon_resource'] = icon
                            
                except Exception as e:
                    print(f"Manifest parsing error: {e}")
        except Exception as e:
            print(f"Additional info extraction error: {e}")
        
        # File size in human readable format
        try:
            file_size_bytes = os.path.getsize(apk_path)
            if file_size_bytes < 1024:
                additional['file_size_human'] = f"{file_size_bytes} B"
            elif file_size_bytes < 1024 * 1024:
                additional['file_size_human'] = f"{file_size_bytes / 1024:.1f} KB"
            else:
                additional['file_size_human'] = f"{file_size_bytes / (1024 * 1024):.1f} MB"
        except:
            additional['file_size_human'] = "Unknown"
        
        # Component counts for display
        try:
            additional['component_summary'] = {
                'activities': len(a.get_activities() or []),
                'services': len(a.get_services() or []),
                'receivers': len(a.get_receivers() or []),
                'providers': len(a.get_providers() or [])
            }
        except:
            additional['component_summary'] = {
                'activities': 0,
                'services': 0,
                'receivers': 0,
                'providers': 0
            }
        
        # APK creation/modification time
        try:
            import time
            stat = os.stat(apk_path)
            additional['file_modified'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_mtime))
        except:
            additional['file_modified'] = "Unknown"
        
        return additional
