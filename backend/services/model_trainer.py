"""
Simple ML Model Trainer for APK Risk Assessment
Creates and trains a basic model when no pre-trained model is available.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os
from typing import Dict, List, Any, Tuple

class SimpleModelTrainer:
    """Train a basic ML model for APK risk assessment"""
    
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_columns = [
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
    
    def create_synthetic_training_data(self, n_samples: int = 1000) -> Tuple[pd.DataFrame, np.ndarray]:
        """Create synthetic training data for basic model training"""
        np.random.seed(42)
        
        data = []
        labels = []
        
        for i in range(n_samples):
            # Create synthetic APK features
            features = {}
            
            # Determine if this should be malicious (30% malicious)
            is_malicious = np.random.random() < 0.3
            
            if is_malicious:
                # Malicious APK characteristics
                features['total_permissions'] = np.random.randint(8, 25)
                features['dangerous_permissions'] = np.random.randint(5, 15)
                features['has_system_alert_window'] = np.random.choice([0, 1], p=[0.3, 0.7])
                features['has_bind_accessibility_service'] = np.random.choice([0, 1], p=[0.4, 0.6])
                features['has_bind_device_admin'] = np.random.choice([0, 1], p=[0.5, 0.5])
                features['has_read_sms'] = np.random.choice([0, 1], p=[0.3, 0.7])
                features['has_send_sms'] = np.random.choice([0, 1], p=[0.4, 0.6])
                features['has_receive_sms'] = np.random.choice([0, 1], p=[0.4, 0.6])
                features['is_self_signed'] = np.random.choice([0, 1], p=[0.2, 0.8])
                features['cert_valid'] = np.random.choice([0, 1], p=[0.3, 0.7])
                features['suspicious_strings_count'] = np.random.randint(3, 20)
                features['has_ip_address'] = np.random.choice([0, 1], p=[0.4, 0.6])
                features['has_banking_keywords'] = np.random.choice([0, 1], p=[0.3, 0.7])
                features['sensitive_api_runtime'] = np.random.randint(10, 50)
                features['suspicious_syscalls'] = np.random.randint(5, 30)
                features['malicious_behavior_score'] = np.random.uniform(20, 100)
                features['target_sdk'] = np.random.randint(16, 28)
            else:
                # Benign APK characteristics
                features['total_permissions'] = np.random.randint(3, 12)
                features['dangerous_permissions'] = np.random.randint(0, 6)
                features['has_system_alert_window'] = np.random.choice([0, 1], p=[0.9, 0.1])
                features['has_bind_accessibility_service'] = np.random.choice([0, 1], p=[0.95, 0.05])
                features['has_bind_device_admin'] = np.random.choice([0, 1], p=[0.9, 0.1])
                features['has_read_sms'] = np.random.choice([0, 1], p=[0.8, 0.2])
                features['has_send_sms'] = np.random.choice([0, 1], p=[0.9, 0.1])
                features['has_receive_sms'] = np.random.choice([0, 1], p=[0.8, 0.2])
                features['is_self_signed'] = np.random.choice([0, 1], p=[0.7, 0.3])
                features['cert_valid'] = np.random.choice([0, 1], p=[0.1, 0.9])
                features['suspicious_strings_count'] = np.random.randint(0, 5)
                features['has_ip_address'] = np.random.choice([0, 1], p=[0.8, 0.2])
                features['has_banking_keywords'] = np.random.choice([0, 1], p=[0.9, 0.1])
                features['sensitive_api_runtime'] = np.random.randint(0, 15)
                features['suspicious_syscalls'] = np.random.randint(0, 10)
                features['malicious_behavior_score'] = np.random.uniform(0, 25)
                features['target_sdk'] = np.random.randint(26, 34)
            
            # Common features for both
            features['permission_ratio'] = features['dangerous_permissions'] / max(features['total_permissions'], 1)
            features['has_camera'] = np.random.choice([0, 1], p=[0.6, 0.4])
            features['has_record_audio'] = np.random.choice([0, 1], p=[0.7, 0.3])
            features['min_sdk'] = max(1, features['target_sdk'] - np.random.randint(0, 10))
            features['version_code'] = np.random.randint(1, 100)
            features['file_size_mb'] = np.random.uniform(1, 50)
            features['activities_count'] = np.random.randint(1, 20)
            features['services_count'] = np.random.randint(0, 15)
            features['receivers_count'] = np.random.randint(0, 10)
            features['suspicious_domain_hits'] = np.random.randint(0, 5)
            
            # Ensure all required features are present
            for col in self.feature_columns:
                if col not in features:
                    features[col] = 0
            
            data.append(features)
            labels.append(1 if is_malicious else 0)
        
        df = pd.DataFrame(data)
        return df[self.feature_columns], np.array(labels)
    
    def train_model(self, save_path: str = None) -> Tuple[float, str]:
        """Train a basic Random Forest model"""
        print("Creating synthetic training data...")
        X, y = self.create_synthetic_training_data(1000)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train Random Forest
        print("Training Random Forest model...")
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42
        )
        
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"Model trained with accuracy: {accuracy:.3f}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        
        # Save model if path provided
        if save_path:
            model_dir = os.path.dirname(save_path)
            os.makedirs(model_dir, exist_ok=True)
            
            model_path = os.path.join(model_dir, 'apkshield_model.joblib')
            scaler_path = os.path.join(model_dir, 'preproc.joblib')
            
            joblib.dump(self.model, model_path)
            joblib.dump(self.scaler, scaler_path)
            
            print(f"Model saved to: {model_path}")
            print(f"Scaler saved to: {scaler_path}")
            
            return accuracy, f"Model saved successfully to {model_dir}"
        
        return accuracy, "Model trained but not saved"
    
    def create_models_if_missing(self, model_dir: str) -> bool:
        """Create and save models if they don't exist"""
        model_path = os.path.join(model_dir, 'apkshield_model.joblib')
        scaler_path = os.path.join(model_dir, 'preproc.joblib')
        
        if not os.path.exists(model_path) or not os.path.exists(scaler_path):
            print("ML models not found, creating new ones...")
            try:
                accuracy, message = self.train_model(model_dir)
                print(f"Model creation completed: {message}")
                return True
            except Exception as e:
                print(f"Failed to create models: {e}")
                return False
        else:
            print("ML models already exist")
            return True

def ensure_models_exist(model_dir: str) -> bool:
    """Utility function to ensure ML models exist"""
    trainer = SimpleModelTrainer()
    return trainer.create_models_if_missing(model_dir)
