import joblib
import pandas as pd
import numpy as np
from typing import Dict, List, Any
from sklearn.calibration import CalibratedClassifierCV
import os
import sys
from .enhanced_risk_scorer import EnhancedRiskScorer

# Add ML folder to path for importing feature extractors
ml_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'ml')
if ml_path not in sys.path:
    sys.path.append(ml_path)

try:
    from static_feature_extractor import DANGEROUS_PERMISSIONS as ML_DANGEROUS_PERMISSIONS
    from dynamic_feature_extractor import create_mock_dynamic_features
    ML_FEATURE_NAMES = [
        'total_permissions', 'sensitive_api_count', 'obfuscation_score',
        'exported_components', 'has_native_code', 'pkg_has_bank_keyword',
        'sensitive_api_runtime', 'suspicious_syscalls', 'suspicious_domain_hits',
        'malicious_behavior_score'
    ]
except ImportError:
    ML_FEATURE_NAMES = []
    print("Warning: ML feature extractors not available for predictor")

class MLPredictor:
    """ML model predictor for APK risk assessment"""
    
    def __init__(self, model_path: str = None, preproc_path: str = None):
        """Initialize with trained model and preprocessor"""
        self.model = None
        self.preprocessor = None
        self.feature_names = None
        self.enhanced_scorer = EnhancedRiskScorer()
        
        # Try to load ML models if paths provided
        if model_path and preproc_path:
            try:
                if os.path.exists(model_path) and os.path.exists(preproc_path):
                    # Suppress sklearn version warnings during model loading
                    import warnings
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
                        warnings.filterwarnings("ignore", message=".*InconsistentVersionWarning.*")
                        self.model = joblib.load(model_path)
                        self.preprocessor = joblib.load(preproc_path)
                    
                    self.feature_names = self.preprocessor.get_feature_names_out() if hasattr(self.preprocessor, 'get_feature_names_out') else None
                    print("✅ ML model loaded from", model_path)
                else:
                    print("ML model files not found, using enhanced rule-based analysis")
            except Exception as e:
                print(f"Failed to load ML models: {e}, using enhanced rule-based analysis")
        
    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Predict risk score and provide explanations"""
        try:
            # Use ML model if available
            if self.model and self.preprocessor:
                return self._ml_predict(features)
            else:
                # Use enhanced rule-based scoring
                return self._enhanced_rule_predict(features)
                
        except Exception as e:
            print(f"Prediction error: {e}, falling back to enhanced rule-based analysis")
            return self._enhanced_rule_predict(features)
    
    def _ml_predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Perform ML-based prediction"""
        try:
            # Use standardized ML features if available
            ml_features = features.get('ml_features', features)
            
            print(f"🤖 ML Prediction - Input features: {len(ml_features)}")
            print(f"🔍 Key features: dangerous_permissions={ml_features.get('dangerous_permissions', 0)}, "
                  f"total_permissions={ml_features.get('total_permissions', 0)}, "
                  f"malicious_behavior_score={ml_features.get('malicious_behavior_score', 0)}")
            
            # Prepare features for ML model
            feature_df = pd.DataFrame([ml_features])
            
            # Use only features that the model was trained on
            expected_features = self.preprocessor.feature_names_in_ if hasattr(self.preprocessor, 'feature_names_in_') else list(ml_features.keys())
            
            # Filter to only expected features
            available_features = [f for f in expected_features if f in feature_df.columns]
            missing_features = [f for f in expected_features if f not in feature_df.columns]
            
            if missing_features:
                print(f"❌ Missing features for ML prediction: {missing_features[:5]}...")
                return self._enhanced_rule_predict(features)
            
            print(f"✅ Using {len(available_features)} features for ML prediction")
            
            # Select only available features
            feature_df = feature_df[available_features]
            
            # Preprocess features
            X = self.preprocessor.transform(feature_df)
            
            # Get prediction and probability
            prediction = self.model.predict(X)[0]
            probabilities = self.model.predict_proba(X)[0]
            
            print(f"🎯 ML Prediction: {prediction}, Probabilities: {probabilities}")
            
            # Get feature importance
            feature_importance = self._get_feature_importance(available_features, X)
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(prediction, probabilities, ml_features)
            
            print(f"📊 Final ML risk score: {risk_score}")
            
            # Safe confidence calculation with NaN protection
            import math
            confidence = max(probabilities) if probabilities is not None and len(probabilities) > 0 else 0.5
            if math.isnan(confidence) or math.isinf(confidence):
                confidence = 0.5
            
            # Safe probability calculation
            safe_prob = probabilities[0] if len(probabilities) > 1 else (1 - probabilities[0] if len(probabilities) > 0 else 0.5)
            malicious_prob = probabilities[1] if len(probabilities) > 1 else (probabilities[0] if len(probabilities) > 0 else 0.5)
            
            # NaN protection for probabilities
            if math.isnan(safe_prob) or math.isinf(safe_prob):
                safe_prob = 0.5
            if math.isnan(malicious_prob) or math.isinf(malicious_prob):
                malicious_prob = 0.5
            
            # Ensure probabilities sum to 1
            total_prob = safe_prob + malicious_prob
            if total_prob > 0:
                safe_prob = safe_prob / total_prob
                malicious_prob = malicious_prob / total_prob
            else:
                safe_prob = 0.5
                malicious_prob = 0.5
            
            print(f"📈 Confidence: {confidence:.3f}, Safe: {safe_prob:.3f}, Malicious: {malicious_prob:.3f}")
            
            return {
                'prediction': int(prediction),
                'risk_score': float(risk_score),
                'confidence': float(confidence),
                'probabilities': {
                    'safe': float(safe_prob),
                    'malicious': float(malicious_prob)
                },
                'feature_importance': feature_importance,
                'method': 'ml'
            }
            
        except Exception as e:
            print(f"❌ ML prediction error: {str(e)}")
            return self._enhanced_rule_predict(features)
    
    def _enhanced_rule_predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced rule-based prediction using sophisticated scoring"""
        print("Using enhanced rule-based analysis")
        
        # Use enhanced risk scorer
        risk_score, top_features = self.enhanced_scorer.calculate_enhanced_risk_score(features)
        verdict = self.enhanced_scorer.get_verdict(risk_score)
        
        print(f"🎯 Enhanced scorer returned {len(top_features)} features with importance values")
        
        # Calculate confidence based on number of risk factors with NaN protection
        import math
        confidence = min(0.95, len(top_features) * 0.15 + 0.3) if top_features else 0.5
        if math.isnan(confidence) or math.isinf(confidence):
            confidence = 0.5
        
        # Calculate probabilities from risk score
        malicious_prob = min(1.0, risk_score / 10.0)
        safe_prob = 1.0 - malicious_prob
        
        return {
            'prediction': 1 if risk_score > 5.0 else 0,
            'risk_score': float(risk_score),
            'verdict': verdict,
            'confidence': float(confidence),
            'probabilities': {
                'safe': float(safe_prob),
                'malicious': float(malicious_prob)
            },
            'feature_importance': top_features,
            'method': 'enhanced_rule'
        }
    
    def _calibrate_risk_score(self, probability: float) -> float:
        """Convert probability to 0-10 risk score with better variance"""
        import random
        
        # Base score from probability
        base_score = probability * 10
        
        # Add variance based on probability ranges
        if probability < 0.2:  # Low risk
            variance = random.uniform(-0.5, 1.0)
            final_score = max(0, min(3, base_score + variance))
        elif probability < 0.4:  # Medium-low risk
            variance = random.uniform(-1.0, 1.5)
            final_score = max(1, min(5, base_score + variance))
        elif probability < 0.6:  # Medium risk
            variance = random.uniform(-1.5, 2.0)
            final_score = max(2, min(7, base_score + variance))
        elif probability < 0.8:  # High risk
            variance = random.uniform(-1.0, 2.5)
            final_score = max(4, min(9, base_score + variance))
        else:  # Very high risk
            variance = random.uniform(-0.5, 1.5)
            final_score = max(6, min(10, base_score + variance))
        
        return round(final_score, 1)
    
    def _get_verdict(self, risk_score: float) -> str:
        """Convert risk score to verdict"""
        if risk_score < 3.0:
            return "Safe"
        elif risk_score < 7.0:
            return "Suspicious"
        else:
            return "High Risk"
    
    def _get_feature_importance(self, original_features: Dict[str, Any], processed_features: np.ndarray) -> List[Dict[str, float]]:
        """Get top contributing features for explainability"""
        try:
            # Try to get model-based feature importance
            importances = None
            feature_names = None
            
            if hasattr(self.model, 'feature_importances_'):
                # Tree-based models
                importances = self.model.feature_importances_
            elif hasattr(self.model, 'coef_'):
                # Linear models
                importances = np.abs(self.model.coef_[0] if len(self.model.coef_.shape) > 1 else self.model.coef_)
            
            # Get feature names
            if self.feature_names is not None:
                feature_names = self.feature_names
            elif importances is not None:
                feature_names = [f"feature_{i}" for i in range(len(importances))]
            
            # If we have model importances, use them
            if importances is not None and feature_names is not None:
                feature_importance = list(zip(feature_names, importances))
                feature_importance.sort(key=lambda x: x[1], reverse=True)
                
                top_features = []
                for name, importance in feature_importance[:5]:
                    original_name = self._map_to_original_feature(name, original_features)
                    if original_name in original_features:
                        # Ensure importance is a valid number
                        import math
                        safe_importance = float(importance) if importance is not None else 0.0
                        if math.isnan(safe_importance) or math.isinf(safe_importance):
                            safe_importance = 0.0
                        
                        top_features.append({
                            'feature': original_name,
                            'importance': safe_importance,
                            'value': original_features.get(original_name, 'N/A')
                        })
                
                if top_features:
                    return top_features
            
            # Fallback: Create rule-based feature importance based on feature values
            return self._create_rule_based_importance(original_features)
            
        except Exception as e:
            print(f"Feature importance error: {e}")
            return self._create_rule_based_importance(original_features)
    
    def _create_rule_based_importance(self, features: Dict[str, Any]) -> List[Dict[str, float]]:
        """Create comprehensive feature importance with detailed analysis"""
        print(f"Creating rule-based importance from features: {features}")
        importance_rules = []
        
        # Enhanced dangerous permissions analysis
        dangerous_perms = features.get('dangerous_permissions', 0)
        total_perms = features.get('total_permissions', 0)
        
        if dangerous_perms > 15:
            importance_rules.append({
                'feature': 'Critical Permission Count',
                'importance': 0.95,
                'value': f"{dangerous_perms} dangerous permissions",
                'explanation': 'Extremely high number of dangerous permissions'
            })
        elif dangerous_perms > 8:
            importance_rules.append({
                'feature': 'High Permission Risk',
                'importance': 0.8,
                'value': f"{dangerous_perms} dangerous permissions",
                'explanation': 'Many dangerous permissions requested'
            })
        elif dangerous_perms > 3:
            importance_rules.append({
                'feature': 'Moderate Permission Risk',
                'importance': 0.5,
                'value': f"{dangerous_perms} dangerous permissions",
                'explanation': 'Several dangerous permissions'
            })
        elif dangerous_perms > 0:
            importance_rules.append({
                'feature': 'Low Permission Risk',
                'importance': 0.3,
                'value': f"{dangerous_perms} dangerous permissions",
                'explanation': 'Few dangerous permissions'
            })
        
        # Permission ratio analysis with NaN protection
        perm_ratio = features.get('permission_ratio', 0)
        import math
        if math.isnan(perm_ratio) or math.isinf(perm_ratio):
            perm_ratio = 0
        
        if perm_ratio > 0.7:
            importance_rules.append({
                'feature': 'Very High Permission Ratio',
                'importance': 0.9,
                'value': f"{perm_ratio:.1%}",
                'explanation': 'Most permissions are dangerous'
            })
        elif perm_ratio > 0.4:
            importance_rules.append({
                'feature': 'High Permission Ratio',
                'importance': 0.6,
                'value': f"{perm_ratio:.1%}",
                'explanation': 'High ratio of dangerous permissions'
            })
        elif perm_ratio > 0.2:
            importance_rules.append({
                'feature': 'Moderate Permission Ratio',
                'importance': 0.4,
                'value': f"{perm_ratio:.1%}",
                'explanation': 'Moderate dangerous permission ratio'
            })
        
        # Certificate analysis
        if features.get('is_self_signed', 0) == 1:
            importance_rules.append({
                'feature': 'Self-Signed Certificate',
                'importance': 0.7,
                'value': 'Yes',
                'explanation': 'Not signed by trusted authority'
            })
        else:
            importance_rules.append({
                'feature': 'Valid Certificate',
                'importance': 0.2,
                'value': 'Yes',
                'explanation': 'Properly signed certificate'
            })
        
        # Suspicious content analysis
        suspicious_count = features.get('suspicious_strings_count', 0)
        if suspicious_count > 15:
            importance_rules.append({
                'feature': 'High Suspicious Content',
                'importance': 0.85,
                'value': f"{suspicious_count} patterns",
                'explanation': 'Many suspicious code patterns found'
            })
        elif suspicious_count > 5:
            importance_rules.append({
                'feature': 'Moderate Suspicious Content',
                'importance': 0.6,
                'value': f"{suspicious_count} patterns",
                'explanation': 'Several suspicious patterns detected'
            })
        elif suspicious_count > 0:
            importance_rules.append({
                'feature': 'Low Suspicious Content',
                'importance': 0.3,
                'value': f"{suspicious_count} patterns",
                'explanation': 'Few suspicious patterns found'
            })
        
        # Banking and financial indicators
        if features.get('has_banking_keywords', 0) == 1:
            importance_rules.append({
                'feature': 'Banking Keywords Detected',
                'importance': 0.8,
                'value': 'Yes',
                'explanation': 'Contains financial/banking terminology'
            })
        
        # Overlay permission (critical for banking trojans)
        if features.get('has_overlay_permission', 0) == 1:
            importance_rules.append({
                'feature': 'Screen Overlay Permission',
                'importance': 0.9,
                'value': 'Yes',
                'explanation': 'Can display overlays over other apps'
            })
        
        # Network and communication risks
        if features.get('has_ip_address', 0) == 1:
            importance_rules.append({
                'feature': 'Hardcoded IP Addresses',
                'importance': 0.6,
                'value': 'Yes',
                'explanation': 'Contains hardcoded network addresses'
            })
        
        # Administrative privileges
        if features.get('requests_admin_rights', 0) == 1:
            importance_rules.append({
                'feature': 'Admin Rights Request',
                'importance': 0.8,
                'value': 'Yes',
                'explanation': 'Requests device administrator privileges'
            })
        
        # SMS capabilities
        if features.get('sends_sms', 0) == 1:
            importance_rules.append({
                'feature': 'SMS Sending Capability',
                'importance': 0.7,
                'value': 'Yes',
                'explanation': 'Can send SMS messages'
            })
        
        # File size analysis with NaN protection
        file_size = features.get('file_size_mb', 0)
        if math.isnan(file_size) or math.isinf(file_size):
            file_size = 0
        
        if file_size > 100:
            importance_rules.append({
                'feature': 'Very Large App Size',
                'importance': 0.5,
                'value': f"{file_size:.1f} MB",
                'explanation': 'Unusually large for mobile app'
            })
        elif file_size > 50:
            importance_rules.append({
                'feature': 'Large App Size',
                'importance': 0.3,
                'value': f"{file_size:.1f} MB",
                'explanation': 'Above average size'
            })
        elif file_size < 1 and file_size > 0:
            importance_rules.append({
                'feature': 'Very Small App Size',
                'importance': 0.4,
                'value': f"{file_size:.1f} MB",
                'explanation': 'Unusually small - possible dropper'
            })
        
        # SDK version analysis
        target_sdk = features.get('target_sdk', 0)
        if target_sdk > 0 and target_sdk < 21:
            importance_rules.append({
                'feature': 'Very Outdated SDK',
                'importance': 0.6,
                'value': f"API {target_sdk}",
                'explanation': 'Targets very old Android version'
            })
        elif target_sdk > 0 and target_sdk < 26:
            importance_rules.append({
                'feature': 'Outdated SDK',
                'importance': 0.4,
                'value': f"API {target_sdk}",
                'explanation': 'Targets older Android version'
            })
        
        # Native code usage
        if features.get('uses_native_code', 0) == 1:
            importance_rules.append({
                'feature': 'Native Code Usage',
                'importance': 0.4,
                'value': 'Yes',
                'explanation': 'Uses native libraries (harder to analyze)'
            })
        
        # Ensure we always have some features to display
        if not importance_rules:
            importance_rules.append({
                'feature': 'Basic App Analysis',
                'importance': 0.3,
                'value': f"{total_perms} total permissions",
                'explanation': 'Standard permission analysis'
            })
        
        # Ensure all importance values are valid numbers
        for rule in importance_rules:
            importance = rule.get('importance', 0)
            if math.isnan(importance) or math.isinf(importance):
                rule['importance'] = 0.0
            else:
                rule['importance'] = float(importance)
        
        # Sort by importance and return top features
        importance_rules.sort(key=lambda x: x['importance'], reverse=True)
        
        print(f"Created {len(importance_rules)} rule-based features")
        return importance_rules[:8]  # Return top 8 features
    
    def _map_to_original_feature(self, processed_name: str, original_features: Dict[str, Any]) -> str:
        """Map processed feature name back to original"""
        # Handle one-hot encoded features
        for orig_name in original_features.keys():
            if orig_name.lower() in processed_name.lower():
                return orig_name
        
        # Handle transformed names
        name_mapping = {
            'total_permissions': 'Total Permissions',
            'dangerous_permissions': 'Dangerous Permissions',
            'permission_ratio': 'Permission Ratio',
            'is_self_signed': 'Self-signed Certificate',
            'suspicious_strings_count': 'Suspicious Strings',
            'has_ip_address': 'Contains IP Address',
            'has_banking_keywords': 'Banking Keywords',
            'file_size_mb': 'File Size (MB)'
        }
        
        return name_mapping.get(processed_name, processed_name)
