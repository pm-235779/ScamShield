#!/usr/bin/env python3
"""
Demo script to show the banking trojan detection model working
Creates synthetic data, trains model, and makes predictions
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
from xgboost import XGBClassifier
import joblib
import os
from pathlib import Path

def create_synthetic_dataset(n_malware=300, n_benign=300):
    """Create synthetic dataset for demonstration."""
    print("🔄 Creating synthetic dataset...")
    np.random.seed(42)
    features = []
    
    # Generate malware features (higher risk values)
    for i in range(n_malware):
        feature = {
            'total_permissions': np.random.randint(15, 40),
            'sensitive_api_count': np.random.randint(10, 50),
            'obfuscation_score': np.random.randint(20, 200),
            'exported_components': np.random.randint(2, 15),
            'has_native_code': np.random.choice([0, 1], p=[0.4, 0.6]),
            'pkg_has_bank_keyword': np.random.choice([0, 1], p=[0.3, 0.7]),
            'sensitive_api_runtime': np.random.randint(10, 60),
            'suspicious_syscalls': np.random.randint(5, 40),
            'suspicious_domain_hits': np.random.randint(1, 8),
            'malicious_behavior_score': np.random.uniform(10, 50),
            'perm_read_sms': np.random.choice([0, 1], p=[0.3, 0.7]),
            'perm_send_sms': np.random.choice([0, 1], p=[0.4, 0.6]),
            'perm_read_contacts': np.random.choice([0, 1], p=[0.3, 0.7]),
            'perm_accessibility_service': np.random.choice([0, 1], p=[0.2, 0.8]),
            'label': 1
        }
        features.append(feature)
    
    # Generate benign features (lower risk values)
    for i in range(n_benign):
        feature = {
            'total_permissions': np.random.randint(8, 25),
            'sensitive_api_count': np.random.randint(0, 15),
            'obfuscation_score': np.random.randint(0, 50),
            'exported_components': np.random.randint(0, 8),
            'has_native_code': np.random.choice([0, 1], p=[0.6, 0.4]),
            'pkg_has_bank_keyword': np.random.choice([0, 1], p=[0.2, 0.8]),
            'sensitive_api_runtime': np.random.randint(0, 20),
            'suspicious_syscalls': np.random.randint(0, 15),
            'suspicious_domain_hits': np.random.randint(0, 3),
            'malicious_behavior_score': np.random.uniform(0, 15),
            'perm_read_sms': np.random.choice([0, 1], p=[0.8, 0.2]),
            'perm_send_sms': np.random.choice([0, 1], p=[0.9, 0.1]),
            'perm_read_contacts': np.random.choice([0, 1], p=[0.7, 0.3]),
            'perm_accessibility_service': np.random.choice([0, 1], p=[0.9, 0.1]),
            'label': 0
        }
        features.append(feature)
    
    df = pd.DataFrame(features)
    print(f"✅ Created dataset with {len(df)} samples")
    print(f"   - Malware: {(df['label'] == 1).sum()}")
    print(f"   - Benign: {(df['label'] == 0).sum()}")
    return df

def train_model(df):
    """Train XGBoost model."""
    print("\n🤖 Training XGBoost model...")
    
    # Prepare features
    feature_columns = [col for col in df.columns if col != 'label']
    X = df[feature_columns]
    y = df['label']
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    
    print(f"   - Training samples: {len(X_train)}")
    print(f"   - Test samples: {len(X_test)}")
    
    # Train model
    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.9,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric='logloss'
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]
    
    print("\n📊 Model Performance:")
    print("="*50)
    print(classification_report(y_test, y_pred, digits=3))
    print(f"ROC-AUC Score: {roc_auc_score(y_test, y_pred_proba):.3f}")
    
    # Feature importance
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("\n🎯 Top 5 Most Important Features:")
    for _, row in feature_importance.head(5).iterrows():
        print(f"   {row['feature']}: {row['importance']:.3f}")
    
    return model, X.columns.tolist()

def test_predictions(model, feature_names):
    """Test model with sample predictions."""
    print("\n🔍 Testing Predictions:")
    print("="*50)
    
    # Test cases
    test_cases = [
        {
            'name': 'Suspicious Banking App',
            'features': {
                'total_permissions': 35,
                'sensitive_api_count': 45,
                'obfuscation_score': 150,
                'exported_components': 12,
                'has_native_code': 1,
                'pkg_has_bank_keyword': 1,
                'sensitive_api_runtime': 50,
                'suspicious_syscalls': 30,
                'suspicious_domain_hits': 5,
                'malicious_behavior_score': 40.0,
                'perm_read_sms': 1,
                'perm_send_sms': 1,
                'perm_read_contacts': 1,
                'perm_accessibility_service': 1
            }
        },
        {
            'name': 'Legitimate Banking App',
            'features': {
                'total_permissions': 15,
                'sensitive_api_count': 8,
                'obfuscation_score': 20,
                'exported_components': 3,
                'has_native_code': 1,
                'pkg_has_bank_keyword': 1,
                'sensitive_api_runtime': 5,
                'suspicious_syscalls': 2,
                'suspicious_domain_hits': 0,
                'malicious_behavior_score': 5.0,
                'perm_read_sms': 0,
                'perm_send_sms': 0,
                'perm_read_contacts': 1,
                'perm_accessibility_service': 0
            }
        }
    ]
    
    for test_case in test_cases:
        # Create feature vector
        feature_dict = {name: test_case['features'].get(name, 0) for name in feature_names}
        df = pd.DataFrame([feature_dict])
        
        # Make prediction
        prediction = model.predict(df)[0]
        probability = model.predict_proba(df)[0, 1]
        
        # Determine risk level
        if probability >= 0.8:
            risk_level = "🔴 HIGH"
        elif probability >= 0.5:
            risk_level = "🟡 MEDIUM"
        else:
            risk_level = "🟢 LOW"
        
        label = "MALWARE" if prediction == 1 else "BENIGN"
        
        print(f"\n📱 {test_case['name']}:")
        print(f"   Prediction: {label}")
        print(f"   Confidence: {probability:.1%}")
        print(f"   Risk Level: {risk_level}")

def save_model(model, feature_names):
    """Save the trained model."""
    models_dir = Path("./models")
    models_dir.mkdir(exist_ok=True)
    
    # Save model
    model_path = models_dir / "banking_trojan_detector.joblib"
    joblib.dump(model, model_path)
    
    # Save feature names
    feature_names_path = models_dir / "feature_names.csv"
    pd.Series(feature_names).to_csv(feature_names_path, index=False, header=['feature'])
    
    print(f"\n💾 Model saved to: {model_path}")
    print(f"💾 Feature names saved to: {feature_names_path}")

def main():
    """Main demonstration function."""
    print("🚀 APKShield Banking Trojan Detection Model Demo")
    print("="*60)
    
    # Create synthetic dataset
    df = create_synthetic_dataset()
    
    # Train model
    model, feature_names = train_model(df)
    
    # Test predictions
    test_predictions(model, feature_names)
    
    # Save model
    save_model(model, feature_names)
    
    print("\n✅ Demo completed successfully!")
    print("🎯 The model is now ready to detect banking trojans!")
    print("\nNext steps:")
    print("   - Use 'python scan_apk.py sample.apk' to scan APK files")
    print("   - Use 'python api_server.py' to start the web API")
    print("   - Open the Jupyter notebook for interactive analysis")

if __name__ == "__main__":
    main()
