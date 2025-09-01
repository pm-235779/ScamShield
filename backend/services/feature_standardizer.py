"""
Feature Standardizer for APK Analysis
Ensures extracted features match the trained ML model's expected feature set.
"""

from typing import Dict, Any, List

class FeatureStandardizer:
    """Standardizes features to match the trained model expectations"""
    
    def __init__(self):
        # Expected features by the trained model (from model_trainer.py)
        self.expected_features = [
            'total_permissions', 'dangerous_permissions', 'permission_ratio',
            'has_system_alert_window', 'has_bind_accessibility_service', 
            'has_bind_device_admin', 'has_read_sms', 'has_send_sms',
            'has_receive_sms', 'has_camera', 'has_record_audio',
            'min_sdk', 'target_sdk', 'version_code', 'file_size_mb',
            'is_self_signed', 'cert_valid', 'activities_count',
            'services_count', 'receivers_count', 'suspicious_strings_count',
            'has_ip_address', 'has_banking_keywords', 'sensitive_api_runtime',
            'suspicious_syscalls', 'suspicious_domain_hits', 'malicious_behavior_score'
        ]
    
    def standardize_features(self, raw_features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert raw extracted features to standardized model-compatible features
        """
        standardized = {}
        
        # Core permission features with NaN protection
        total_perms = raw_features.get('total_permissions', 0) or 0
        dangerous_perms = raw_features.get('dangerous_permissions', 0) or 0
        
        standardized['total_permissions'] = max(0, int(total_perms))
        standardized['dangerous_permissions'] = max(0, int(dangerous_perms))
        
        # Calculate permission ratio safely
        if total_perms > 0:
            standardized['permission_ratio'] = min(1.0, dangerous_perms / total_perms)
        else:
            standardized['permission_ratio'] = 0.0
        
        # Individual permission flags
        permission_flags = [
            'has_system_alert_window', 'has_bind_accessibility_service', 
            'has_bind_device_admin', 'has_read_sms', 'has_send_sms',
            'has_receive_sms', 'has_camera', 'has_record_audio'
        ]
        
        for flag in permission_flags:
            standardized[flag] = raw_features.get(flag, 0)
        
        # SDK and version info with NaN protection
        standardized['min_sdk'] = max(1, int(raw_features.get('min_sdk', 1) or 1))
        standardized['target_sdk'] = max(1, int(raw_features.get('target_sdk', 28) or 28))
        standardized['version_code'] = max(1, int(raw_features.get('version_code', 1) or 1))
        
        # File size with NaN protection
        file_size = raw_features.get('file_size_mb', raw_features.get('size_mb', 0)) or 0
        standardized['file_size_mb'] = max(0.0, float(file_size))
        
        # Certificate features with NaN protection
        standardized['is_self_signed'] = int(bool(raw_features.get('is_self_signed', 1)))
        standardized['cert_valid'] = int(bool(raw_features.get('cert_valid', 0)))
        
        # Component counts with NaN protection
        standardized['activities_count'] = max(0, int(raw_features.get('activities_count', 0) or 0))
        standardized['services_count'] = max(0, int(raw_features.get('services_count', 0) or 0))
        standardized['receivers_count'] = max(0, int(raw_features.get('receivers_count', 0) or 0))
        
        # Content analysis features
        standardized['suspicious_strings_count'] = self._calculate_suspicious_strings(raw_features)
        standardized['has_ip_address'] = self._detect_ip_addresses(raw_features)
        standardized['has_banking_keywords'] = self._detect_banking_keywords(raw_features)
        
        # Dynamic behavior features (calculated from static features)
        standardized['sensitive_api_runtime'] = self._calculate_sensitive_api_runtime(raw_features)
        standardized['suspicious_syscalls'] = self._calculate_suspicious_syscalls(raw_features)
        standardized['suspicious_domain_hits'] = self._calculate_suspicious_domains(raw_features)
        standardized['malicious_behavior_score'] = self._calculate_malicious_behavior_score(standardized)
        
        # Ensure all expected features are present with default values and NaN protection
        for feature in self.expected_features:
            if feature not in standardized:
                standardized[feature] = 0
            else:
                # Protect against NaN values
                value = standardized[feature]
                if isinstance(value, (int, float)):
                    import math
                    if math.isnan(value) or math.isinf(value):
                        standardized[feature] = 0
                    else:
                        standardized[feature] = float(value)
                else:
                    standardized[feature] = 0
        
        # Remove any unexpected features
        final_features = {k: v for k, v in standardized.items() if k in self.expected_features}
        
        print(f"✅ Standardized {len(final_features)} features with NaN protection")
        return final_features
    
    def _calculate_suspicious_strings(self, features: Dict[str, Any]) -> int:
        """Calculate suspicious strings count from various sources"""
        # From package name analysis
        package = features.get('package_name', '').lower()
        app_name = features.get('app_name', '').lower()
        
        suspicious_count = 0
        
        # Check for suspicious patterns in package/app name
        suspicious_patterns = ['test', 'tmp', 'temp', 'fake', 'malware', 'trojan']
        for pattern in suspicious_patterns:
            if pattern in package or pattern in app_name:
                suspicious_count += 1
        
        # Add from existing count if available
        suspicious_count += features.get('suspicious_strings_count', 0)
        
        return min(suspicious_count, 20)  # Cap at reasonable value
    
    def _detect_ip_addresses(self, features: Dict[str, Any]) -> int:
        """Detect if APK contains hardcoded IP addresses"""
        # Check package name for IP-like patterns
        package = features.get('package_name', '')
        import re
        
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        if re.search(ip_pattern, package):
            return 1
        
        return features.get('has_ip_address', 0)
    
    def _detect_banking_keywords(self, features: Dict[str, Any]) -> int:
        """Detect banking-related keywords"""
        package = features.get('package_name', '').lower()
        app_name = features.get('app_name', '').lower()
        
        banking_keywords = [
            'bank', 'banking', 'finance', 'payment', 'wallet', 'money',
            'pay', 'card', 'credit', 'debit', 'upi', 'paytm', 'phonepe',
            'gpay', 'sbi', 'icici', 'hdfc', 'axis', 'kotak'
        ]
        
        for keyword in banking_keywords:
            if keyword in package or keyword in app_name:
                return 1
        
        return features.get('has_banking_keywords', 0)
    
    def _calculate_sensitive_api_runtime(self, features: Dict[str, Any]) -> int:
        """Calculate sensitive API runtime calls based on permissions"""
        base_count = features.get('sensitive_api_runtime', 0)
        
        # Estimate based on dangerous permissions
        dangerous_perms = features.get('dangerous_permissions', 0)
        estimated_calls = dangerous_perms * 2
        
        # Add bonus for critical permissions
        critical_perms = [
            'has_system_alert_window', 'has_bind_accessibility_service',
            'has_bind_device_admin', 'has_read_sms', 'has_send_sms'
        ]
        
        critical_count = sum(features.get(perm, 0) for perm in critical_perms)
        estimated_calls += critical_count * 5
        
        return max(base_count, estimated_calls)
    
    def _calculate_suspicious_syscalls(self, features: Dict[str, Any]) -> int:
        """Calculate suspicious system calls based on app characteristics"""
        base_count = features.get('suspicious_syscalls', 0)
        
        # Estimate based on services and receivers (more components = more syscalls)
        services = features.get('services_count', 0)
        receivers = features.get('receivers_count', 0)
        
        estimated_calls = services * 3 + receivers * 2
        
        # Add for dangerous permissions
        dangerous_perms = features.get('dangerous_permissions', 0)
        estimated_calls += dangerous_perms * 2
        
        return max(base_count, min(estimated_calls, 100))  # Cap at 100
    
    def _calculate_suspicious_domains(self, features: Dict[str, Any]) -> int:
        """Calculate suspicious domain hits"""
        base_count = features.get('suspicious_domain_hits', 0)
        
        # Estimate based on network-related permissions and IP addresses
        has_internet = features.get('total_permissions', 0) > 0  # Assume internet if has permissions
        has_ip = features.get('has_ip_address', 0)
        
        if has_internet and has_ip:
            return max(base_count, 1)
        
        return base_count
    
    def _calculate_malicious_behavior_score(self, features: Dict[str, Any]) -> float:
        """Calculate overall malicious behavior score"""
        score = 0.0
        
        # Permission-based scoring
        dangerous_perms = features.get('dangerous_permissions', 0)
        total_perms = features.get('total_permissions', 1)
        perm_ratio = features.get('permission_ratio', 0)
        
        score += dangerous_perms * 3  # Base score for dangerous permissions
        score += perm_ratio * 15      # Ratio-based scoring
        
        # Critical permission combinations
        overlay = features.get('has_system_alert_window', 0)
        accessibility = features.get('has_bind_accessibility_service', 0)
        admin = features.get('has_bind_device_admin', 0)
        sms_read = features.get('has_read_sms', 0)
        sms_send = features.get('has_send_sms', 0)
        camera = features.get('has_camera', 0)
        location = features.get('has_access_fine_location', 0)
        
        # Banking trojan signatures
        if overlay and accessibility:
            score += 20  # Screen overlay + accessibility = banking trojan
        if admin and (sms_read or sms_send):
            score += 15  # Admin + SMS control
        if overlay and (sms_read or sms_send):
            score += 12  # Overlay + SMS access
        
        # Privacy invasion score
        privacy_score = camera + location + sms_read
        score += privacy_score * 2
        
        # Certificate issues
        if features.get('is_self_signed', 0):
            score += 8
        if not features.get('cert_valid', 1):
            score += 12
        
        # Content-based scoring
        score += features.get('suspicious_strings_count', 0) * 0.8
        score += features.get('has_ip_address', 0) * 5
        score += features.get('has_banking_keywords', 0) * 6
        
        # Runtime behavior estimation
        score += features.get('sensitive_api_runtime', 0) * 0.3
        score += features.get('suspicious_syscalls', 0) * 0.15
        score += features.get('suspicious_domain_hits', 0) * 8
        
        # Component-based risk
        activities = features.get('activities_count', 0)
        services = features.get('services_count', 0)
        receivers = features.get('receivers_count', 0)
        
        # Too many components can indicate complexity/obfuscation
        if activities > 20:
            score += 3
        if services > 10:
            score += 4
        if receivers > 15:
            score += 3
        
        return round(min(score, 100), 2)  # Cap at 100

def standardize_apk_features(raw_features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main function to standardize APK features for ML model compatibility
    """
    standardizer = FeatureStandardizer()
    return standardizer.standardize_features(raw_features)
