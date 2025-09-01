"""
Enhanced Risk Scoring System for APK Analysis
Provides more accurate and differentiated risk assessments with detailed explanations.
"""

import math
from typing import Dict, List, Any, Tuple

class EnhancedRiskScorer:
    """Enhanced risk scoring with weighted feature analysis"""
    
    def __init__(self):
        # Weight categories for different risk factors
        self.permission_weights = {
            'SYSTEM_ALERT_WINDOW': 3.0,  # Critical for overlay attacks
            'BIND_ACCESSIBILITY_SERVICE': 3.0,  # Critical for banking trojans
            'BIND_DEVICE_ADMIN': 2.5,
            'WRITE_SETTINGS': 2.0,
            'READ_SMS': 2.5,
            'SEND_SMS': 2.5,
            'RECEIVE_SMS': 2.0,
            'READ_PHONE_STATE': 1.5,
            'CALL_PHONE': 1.5,
            'RECORD_AUDIO': 2.0,
            'CAMERA': 1.0,
            'ACCESS_FINE_LOCATION': 1.5,
            'INSTALL_PACKAGES': 2.5,
            'DELETE_PACKAGES': 2.5,
            'WRITE_EXTERNAL_STORAGE': 0.5
        }
        
        # Banking trojan indicators
        self.banking_indicators = [
            'overlay', 'accessibility', 'admin', 'sms', 'bank', 
            'pay', 'card', 'pin', 'wallet', 'finance'
        ]
        
        # Suspicious patterns with weights
        self.suspicious_patterns = {
            'hardcoded_ip': 2.0,
            'tor_domain': 3.0,
            'crypto_keywords': 1.5,
            'banking_keywords': 2.5,
            'obfuscation': 1.5
        }

    def calculate_enhanced_risk_score(self, features: Dict[str, Any]) -> Tuple[float, List[Dict[str, Any]]]:
        """Calculate enhanced risk score with detailed feature analysis"""
        risk_factors = []
        total_score = 0.0
        
        print(f"🔍 Enhanced Risk Scoring - Input features: {len(features)}")
        
        # Permission-based analysis
        dangerous_perms = features.get('dangerous_permissions', [])
        total_perms = features.get('permissions', [])
        
        # Handle both list and integer formats
        if isinstance(dangerous_perms, list):
            dangerous_count = len(dangerous_perms)
        else:
            dangerous_count = dangerous_perms or 0
            
        if isinstance(total_perms, list):
            total_count = len(total_perms)
        else:
            total_count = features.get('total_permissions', 0) or 0
        
        print(f"📋 Permissions: {dangerous_count} dangerous out of {total_count} total")
        
        # Permission ratio analysis
        if total_count > 0:
            perm_ratio = dangerous_count / total_count
            if perm_ratio > 0.5:
                score = 2.5
                risk_factors.append({
                    'feature': 'High Dangerous Permission Ratio',
                    'score': score,
                    'value': f'{perm_ratio:.1%} ({dangerous_count}/{total_count})',
                    'description': 'High ratio of dangerous to total permissions'
                })
                total_score += score
            elif perm_ratio > 0.3:
                score = 1.5
                risk_factors.append({
                    'feature': 'Moderate Permission Risk',
                    'score': score,
                    'value': f'{perm_ratio:.1%} ({dangerous_count}/{total_count})',
                    'description': 'Moderate ratio of dangerous permissions'
                })
                total_score += score
        elif dangerous_count > 0:
            # If we have dangerous permissions but no total count, still score it
            score = dangerous_count * 0.5
            risk_factors.append({
                'feature': 'Dangerous Permissions Detected',
                'score': score,
                'value': f'{dangerous_count} permissions',
                'description': 'Dangerous permissions found'
            })
            total_score += score
        
        # Certificate analysis
        cert_info = features.get('certificate_info', {})
        is_self_signed = cert_info.get('is_self_signed', False) or features.get('is_self_signed', 0)
        cert_valid = cert_info.get('is_valid', True) and features.get('cert_valid', 1)
        
        if is_self_signed:
            score = 1.5
            risk_factors.append({
                'feature': 'Self-Signed Certificate',
                'score': score,
                'value': 'Yes',
                'description': 'App uses self-signed certificate instead of trusted CA'
            })
            total_score += score
        
        if not cert_valid:
            score = 2.0
            risk_factors.append({
                'feature': 'Invalid Certificate',
                'score': score,
                'value': 'Expired/Invalid',
                'description': 'Certificate is expired or invalid'
            })
            total_score += score
        
        # Malicious behavior score from feature standardizer
        malicious_score = features.get('malicious_behavior_score', 0)
        if malicious_score > 50:
            score = 2.5
            risk_factors.append({
                'feature': 'High Malicious Behavior Score',
                'score': score,
                'value': f'{malicious_score:.1f}',
                'description': 'High calculated malicious behavior score'
            })
            total_score += score
        elif malicious_score > 25:
            score = 1.5
            risk_factors.append({
                'feature': 'Moderate Malicious Behavior Score',
                'score': score,
                'value': f'{malicious_score:.1f}',
                'description': 'Moderate calculated malicious behavior score'
            })
            total_score += score
        
        # Banking keywords detection
        has_banking = features.get('has_banking_keywords', 0)
        if has_banking:
            score = 1.0
            risk_factors.append({
                'feature': 'Banking Keywords Detected',
                'score': score,
                'value': 'Yes',
                'description': 'App contains banking-related keywords'
            })
            total_score += score
        
        print(f"📊 Total risk score: {total_score:.2f}, Risk factors: {len(risk_factors)}")
        
        # Convert risk_factors to proper format for feature importance display
        feature_importance_list = []
        total_importance = sum(factor.get('score', 0) for factor in risk_factors)
        
        for factor in risk_factors:
            # Calculate normalized importance (0-1 scale)
            raw_importance = factor.get('score', 0)
            normalized_importance = raw_importance / max(total_importance, 1) if total_importance > 0 else 0
            
            feature_importance_list.append({
                'feature': factor.get('feature', 'Unknown'),
                'importance': min(1.0, max(0.0, normalized_importance)),
                'value': factor.get('value', 'N/A'),
                'explanation': factor.get('description', 'Risk factor detected')
            })
        
        print(f"📊 Total risk score: {total_score:.2f}, Feature importance items: {len(feature_importance_list)}")
        
        return total_score, feature_importance_list

    def _analyze_permissions(self, features: Dict[str, Any]) -> Tuple[float, List[Dict[str, Any]]]:
        """Analyze permission-based risks"""
        risk_score = 0.0
        risk_features = []
        
        dangerous_perms = features.get('dangerous_permissions', 0)
        total_perms = features.get('total_permissions', 0)
        
        # Base permission risk
        if dangerous_perms > 0:
            # Exponential scaling for high permission counts
            perm_risk = min(8.0, 2.0 * math.log(dangerous_perms + 1))
            
            # Check for specific high-risk permissions
            overlay_perm = features.get('has_system_alert_window', 0)
            accessibility_perm = features.get('has_bind_accessibility_service', 0)
            admin_perm = features.get('has_bind_device_admin', 0)
            sms_perms = (features.get('has_read_sms', 0) + 
                        features.get('has_send_sms', 0) + 
                        features.get('has_receive_sms', 0))
            
            # Critical permission combinations (banking trojan signature)
            if overlay_perm and accessibility_perm:
                risk_score += 4.0
                risk_features.append({
                    'feature': 'Critical Permission Combo',
                    'importance': 0.95,
                    'value': 'Overlay + Accessibility',
                    'explanation': 'Can display fake interfaces and capture user input'
                })
            
            if admin_perm and sms_perms >= 2:
                risk_score += 3.5
                risk_features.append({
                    'feature': 'Admin + SMS Control',
                    'importance': 0.9,
                    'value': f'Admin + {sms_perms} SMS permissions',
                    'explanation': 'Can control device and intercept SMS'
                })
            
            # Individual high-risk permissions
            if overlay_perm:
                risk_score += 2.5
                risk_features.append({
                    'feature': 'Screen Overlay Permission',
                    'score': 0.85,
                    'value': 'Yes',
                    'description': 'Can display fake login screens'
                })
            
            if accessibility_perm:
                risk_score += 2.5
                risk_features.append({
                    'feature': 'Accessibility Service',
                    'score': 0.85,
                    'value': 'Yes',
                    'description': 'Can monitor and control user interactions'
                })
            
            # Permission ratio analysis
            perm_ratio = dangerous_perms / max(total_perms, 1)
            if perm_ratio > 0.6:
                risk_score += 2.0
                risk_features.append({
                    'feature': 'High Dangerous Permission Ratio',
                    'score': 0.7,
                    'value': f'{perm_ratio:.1%}',
                    'description': 'Most permissions are dangerous'
                })
            
            # Base dangerous permission count
            if dangerous_perms > 10:
                risk_features.append({
                    'feature': 'Excessive Permissions',
                    'score': 0.8,
                    'value': f'{dangerous_perms} dangerous permissions',
                    'description': 'Requests unusually many dangerous permissions'
                })
            elif dangerous_perms > 5:
                risk_features.append({
                    'feature': 'High Permission Count',
                    'score': 0.6,
                    'value': f'{dangerous_perms} dangerous permissions',
                    'description': 'Requests many dangerous permissions'
                })
        
        return min(risk_score, 8.0), risk_features

    def _analyze_certificate(self, features: Dict[str, Any]) -> Tuple[float, List[Dict[str, Any]]]:
        """Analyze certificate-based risks"""
        risk_score = 0.0
        risk_features = []
        
        is_self_signed = features.get('is_self_signed', 0)
        cert_valid = features.get('cert_valid', 1)
        
        if is_self_signed:
            risk_score += 3.0
            risk_features.append({
                'feature': 'Self-Signed Certificate',
                'importance': 0.75,
                'value': 'Yes',
                'explanation': 'Not signed by trusted certificate authority'
            })
        
        if not cert_valid:
            risk_score += 2.0
            risk_features.append({
                'feature': 'Invalid Certificate',
                'importance': 0.8,
                'value': 'Expired/Invalid',
                'explanation': 'Certificate is expired or invalid'
            })
        
        return risk_score, risk_features

    def _analyze_metadata(self, features: Dict[str, Any]) -> Tuple[float, List[Dict[str, Any]]]:
        """Analyze app metadata risks"""
        risk_score = 0.0
        risk_features = []
        
        # File size analysis
        file_size = features.get('file_size_mb', 0)
        if file_size > 100:
            risk_score += 1.5
            risk_features.append({
                'feature': 'Unusually Large Size',
                'importance': 0.5,
                'value': f'{file_size:.1f} MB',
                'explanation': 'Larger than typical mobile apps'
            })
        elif file_size < 0.5 and file_size > 0:
            risk_score += 2.0
            risk_features.append({
                'feature': 'Suspiciously Small Size',
                'importance': 0.6,
                'value': f'{file_size:.1f} MB',
                'explanation': 'May be a dropper or stub application'
            })
        
        # SDK version analysis
        target_sdk = features.get('target_sdk', 0)
        if target_sdk > 0 and target_sdk < 21:
            risk_score += 2.5
            risk_features.append({
                'feature': 'Very Outdated Target SDK',
                'importance': 0.7,
                'value': f'API {target_sdk}',
                'explanation': 'Targets very old Android version with fewer security features'
            })
        elif target_sdk > 0 and target_sdk < 26:
            risk_score += 1.5
            risk_features.append({
                'feature': 'Outdated Target SDK',
                'importance': 0.5,
                'value': f'API {target_sdk}',
                'explanation': 'Targets older Android version'
            })
        
        # Component analysis
        activities = features.get('activities_count', 0)
        services = features.get('services_count', 0)
        receivers = features.get('receivers_count', 0)
        
        if services > 10:
            risk_score += 1.5
            risk_features.append({
                'feature': 'Excessive Background Services',
                'importance': 0.6,
                'value': f'{services} services',
                'explanation': 'Many background services may indicate malicious behavior'
            })
        
        if receivers > 15:
            risk_score += 1.0
            risk_features.append({
                'feature': 'Many Broadcast Receivers',
                'importance': 0.5,
                'value': f'{receivers} receivers',
                'explanation': 'Listens to many system events'
            })
        
        return risk_score, risk_features

    def _analyze_content(self, features: Dict[str, Any]) -> Tuple[float, List[Dict[str, Any]]]:
        """Analyze content and string-based risks"""
        risk_score = 0.0
        risk_features = []
        
        # Suspicious strings
        suspicious_count = features.get('suspicious_strings_count', 0)
        if suspicious_count > 10:
            risk_score += 3.0
            risk_features.append({
                'feature': 'High Suspicious Content',
                'importance': 0.8,
                'value': f'{suspicious_count} patterns',
                'explanation': 'Contains many suspicious code patterns'
            })
        elif suspicious_count > 3:
            risk_score += 1.5
            risk_features.append({
                'feature': 'Moderate Suspicious Content',
                'importance': 0.6,
                'value': f'{suspicious_count} patterns',
                'explanation': 'Contains several suspicious patterns'
            })
        
        # Banking keywords
        if features.get('has_banking_keywords', 0):
            risk_score += 2.0
            risk_features.append({
                'feature': 'Banking Keywords Present',
                'importance': 0.75,
                'value': 'Yes',
                'explanation': 'Contains banking/financial terminology'
            })
        
        # IP addresses
        if features.get('has_ip_address', 0):
            risk_score += 1.5
            risk_features.append({
                'feature': 'Hardcoded IP Addresses',
                'importance': 0.65,
                'value': 'Yes',
                'explanation': 'Contains hardcoded network addresses'
            })
        
        return risk_score, risk_features

    def _analyze_structure(self, features: Dict[str, Any]) -> Tuple[float, List[Dict[str, Any]]]:
        """Analyze structural risks"""
        risk_score = 0.0
        risk_features = []
        
        # Dynamic behavior indicators
        sensitive_apis = features.get('sensitive_api_runtime', 0)
        if sensitive_apis > 20:
            risk_score += 2.0
            risk_features.append({
                'feature': 'High Sensitive API Usage',
                'importance': 0.7,
                'value': f'{sensitive_apis} calls',
                'explanation': 'Makes many sensitive system calls'
            })
        
        # Malicious behavior score
        malicious_score = features.get('malicious_behavior_score', 0)
        if malicious_score > 50:
            risk_score += 2.5
            risk_features.append({
                'feature': 'High Malicious Behavior Score',
                'importance': 0.8,
                'value': f'{malicious_score:.1f}',
                'explanation': 'Exhibits multiple malicious behavior patterns'
            })
        elif malicious_score > 20:
            risk_score += 1.0
            risk_features.append({
                'feature': 'Moderate Malicious Behavior',
                'importance': 0.5,
                'value': f'{malicious_score:.1f}',
                'explanation': 'Shows some suspicious behavior patterns'
            })
        
        return risk_score, risk_features

    def _get_banking_multiplier(self, features: Dict[str, Any]) -> float:
        """Calculate banking trojan likelihood multiplier"""
        multiplier = 1.0
        
        # Check for banking trojan signature combinations
        overlay = features.get('has_system_alert_window', 0)
        accessibility = features.get('has_bind_accessibility_service', 0)
        admin = features.get('has_bind_device_admin', 0)
        sms_read = features.get('has_read_sms', 0)
        sms_send = features.get('has_send_sms', 0)
        banking_keywords = features.get('has_banking_keywords', 0)
        
        # Classic banking trojan signature
        if overlay and accessibility and (sms_read or sms_send):
            multiplier *= 1.8
        
        # Admin rights with SMS
        if admin and (sms_read or sms_send):
            multiplier *= 1.5
        
        # Banking keywords with dangerous permissions
        if banking_keywords and (overlay or accessibility):
            multiplier *= 1.4
        
        # Self-signed with banking indicators
        if features.get('is_self_signed', 0) and banking_keywords:
            multiplier *= 1.3
        
        return min(multiplier, 2.0)  # Cap at 2x multiplier

    def get_verdict(self, risk_score: float) -> str:
        """Get verdict based on enhanced risk score"""
        if risk_score < 2.0:
            return "Safe"
        elif risk_score < 4.0:
            return "Low Risk"
        elif risk_score < 6.0:
            return "Moderate Risk"
        elif risk_score < 8.0:
            return "High Risk"
        else:
            return "Critical Risk"
