#!/usr/bin/env python3
"""
ML Model Training Pipeline for APK Malware Detection
Trains multiple models and selects the best performer
"""

import pandas as pd
import numpy as np
import joblib
import json
from pathlib import Path
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
from sklearn.calibration import CalibratedClassifierCV
import xgboost as xgb
import optuna
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class APKModelTrainer:
    """Train and evaluate ML models for APK malware detection"""
    
    def __init__(self, data_path: str, models_dir: str = "./models"):
        self.data_path = Path(data_path)
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(exist_ok=True)
        
        self.models = {}
        self.results = {}
        self.best_model = None
        self.best_score = 0
        
    def load_data(self):
        """Load and prepare training data"""
        logger.info(f"Loading data from {self.data_path}")
        
        if self.data_path.suffix == '.parquet':
            df = pd.read_parquet(self.data_path)
        else:
            df = pd.read_csv(self.data_path)
        
        # Separate features and labels
        feature_cols = [col for col in df.columns if col not in ['label', 'apk_hash']]
        X = df[feature_cols]
        y = df['label']
        
        logger.info(f"Loaded {len(df)} samples with {len(feature_cols)} features")
        logger.info(f"Class distribution: {y.value_counts().to_dict()}")
        
        return X, y
    
    def prepare_data(self, X, y, test_size=0.2, val_size=0.15):
        """Split and preprocess data"""
        
        # First split: train+val vs test
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # Second split: train vs val
        val_size_adjusted = val_size / (1 - test_size)
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=val_size_adjusted, random_state=42, stratify=y_temp
        )
        
        logger.info(f"Data split - Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")
        
        # Scale features
        scaler = RobustScaler()  # More robust to outliers than StandardScaler
        X_train_scaled = scaler.fit_transform(X_train)
        X_val_scaled = scaler.transform(X_val)
        X_test_scaled = scaler.transform(X_test)
        
        return (X_train_scaled, X_val_scaled, X_test_scaled, 
                y_train, y_val, y_test, scaler)
    
    def train_baseline_models(self, X_train, y_train, X_val, y_val):
        """Train baseline models"""
        
        # Calculate class weights for imbalanced data
        class_weights = 'balanced'
        
        models_config = {
            'logistic_regression': {
                'model': LogisticRegression(
                    class_weight=class_weights,
                    random_state=42,
                    max_iter=1000
                ),
                'params': {}
            },
            'random_forest': {
                'model': RandomForestClassifier(
                    class_weight=class_weights,
                    random_state=42,
                    n_estimators=100
                ),
                'params': {}
            },
            'xgboost': {
                'model': xgb.XGBClassifier(
                    random_state=42,
                    eval_metric='logloss'
                ),
                'params': {}
            }
        }
        
        results = {}
        
        for name, config in models_config.items():
            logger.info(f"Training {name}...")
            
            model = config['model']
            
            # Handle class weights for XGBoost
            if name == 'xgboost':
                scale_pos_weight = (y_train == 0).sum() / (y_train == 1).sum()
                model.set_params(scale_pos_weight=scale_pos_weight)
            
            # Train model
            model.fit(X_train, y_train)
            
            # Evaluate
            train_score = model.score(X_train, y_train)
            val_score = model.score(X_val, y_val)
            
            # Get probabilities for AUC
            y_val_proba = model.predict_proba(X_val)[:, 1]
            auc_score = roc_auc_score(y_val, y_val_proba)
            
            results[name] = {
                'model': model,
                'train_accuracy': train_score,
                'val_accuracy': val_score,
                'auc_score': auc_score
            }
            
            logger.info(f"{name} - Train: {train_score:.3f}, Val: {val_score:.3f}, AUC: {auc_score:.3f}")
        
        return results
    
    def optimize_best_model(self, X_train, y_train, X_val, y_val):
        """Optimize hyperparameters for the best performing model"""
        
        def objective(trial):
            # XGBoost typically performs well for this type of problem
            params = {
                'n_estimators': trial.suggest_int('n_estimators', 100, 500),
                'max_depth': trial.suggest_int('max_depth', 3, 10),
                'learning_rate': trial.suggest_float('learning_rate', 0.01, 0.3),
                'subsample': trial.suggest_float('subsample', 0.6, 1.0),
                'colsample_bytree': trial.suggest_float('colsample_bytree', 0.6, 1.0),
                'reg_alpha': trial.suggest_float('reg_alpha', 0, 10),
                'reg_lambda': trial.suggest_float('reg_lambda', 0, 10),
            }
            
            scale_pos_weight = (y_train == 0).sum() / (y_train == 1).sum()
            
            model = xgb.XGBClassifier(
                **params,
                scale_pos_weight=scale_pos_weight,
                random_state=42,
                eval_metric='logloss'
            )
            
            # Cross-validation score
            cv_scores = cross_val_score(
                model, X_train, y_train, 
                cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=42),
                scoring='roc_auc'
            )
            
            return cv_scores.mean()
        
        logger.info("Optimizing hyperparameters with Optuna...")
        
        study = optuna.create_study(direction='maximize')
        study.optimize(objective, n_trials=50, timeout=300)  # 5 minutes max
        
        best_params = study.best_params
        logger.info(f"Best parameters: {best_params}")
        
        # Train final model with best parameters
        scale_pos_weight = (y_train == 0).sum() / (y_train == 1).sum()
        
        optimized_model = xgb.XGBClassifier(
            **best_params,
            scale_pos_weight=scale_pos_weight,
            random_state=42,
            eval_metric='logloss'
        )
        
        optimized_model.fit(X_train, y_train)
        
        return optimized_model, best_params
    
    def calibrate_model(self, model, X_train, y_train):
        """Calibrate model probabilities for better risk scoring"""
        logger.info("Calibrating model probabilities...")
        
        calibrated_model = CalibratedClassifierCV(
            model, method='isotonic', cv=3
        )
        calibrated_model.fit(X_train, y_train)
        
        return calibrated_model
    
    def evaluate_final_model(self, model, X_test, y_test, feature_names):
        """Comprehensive evaluation of the final model"""
        
        # Predictions
        y_pred = model.predict(X_test)
        y_proba = model.predict_proba(X_test)[:, 1]
        
        # Metrics
        auc_score = roc_auc_score(y_test, y_proba)
        
        # Classification report
        report = classification_report(y_test, y_pred, output_dict=True)
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        
        # Feature importance (if available)
        feature_importance = None
        if hasattr(model, 'feature_importances_'):
            feature_importance = dict(zip(feature_names, model.feature_importances_))
        elif hasattr(model.base_estimator, 'feature_importances_'):
            feature_importance = dict(zip(feature_names, model.base_estimator.feature_importances_))
        
        results = {
            'auc_score': auc_score,
            'classification_report': report,
            'confusion_matrix': cm.tolist(),
            'feature_importance': feature_importance
        }
        
        logger.info(f"Final model AUC: {auc_score:.3f}")
        logger.info(f"Precision (malware): {report['1']['precision']:.3f}")
        logger.info(f"Recall (malware): {report['1']['recall']:.3f}")
        logger.info(f"F1-score (malware): {report['1']['f1-score']:.3f}")
        
        return results
    
    def save_model_artifacts(self, model, scaler, feature_names, evaluation_results, hyperparams=None):
        """Save trained model and associated artifacts"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save model
        model_path = self.models_dir / "apkshield_model.joblib"
        joblib.dump(model, model_path)
        
        # Save preprocessor
        preproc_path = self.models_dir / "preproc.joblib"
        joblib.dump(scaler, preproc_path)
        
        # Save metadata
        metadata = {
            'model_type': type(model).__name__,
            'feature_names': feature_names,
            'training_timestamp': timestamp,
            'evaluation_results': evaluation_results,
            'hyperparameters': hyperparams,
            'model_version': '1.0'
        }
        
        metadata_path = self.models_dir / "model_metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2, default=str)
        
        logger.info(f"Model saved to: {model_path}")
        logger.info(f"Preprocessor saved to: {preproc_path}")
        logger.info(f"Metadata saved to: {metadata_path}")
        
        return model_path, preproc_path, metadata_path
    
    def train_pipeline(self):
        """Complete training pipeline"""
        
        # Load data
        X, y = self.load_data()
        
        # Prepare data
        X_train, X_val, X_test, y_train, y_val, y_test, scaler = self.prepare_data(X, y)
        
        # Train baseline models
        baseline_results = self.train_baseline_models(X_train, y_train, X_val, y_val)
        
        # Find best baseline model
        best_baseline = max(baseline_results.items(), key=lambda x: x[1]['auc_score'])
        logger.info(f"Best baseline model: {best_baseline[0]} (AUC: {best_baseline[1]['auc_score']:.3f})")
        
        # Optimize best model
        optimized_model, best_params = self.optimize_best_model(X_train, y_train, X_val, y_val)
        
        # Calibrate model
        final_model = self.calibrate_model(optimized_model, X_train, y_train)
        
        # Final evaluation
        evaluation_results = self.evaluate_final_model(final_model, X_test, y_test, X.columns.tolist())
        
        # Save artifacts
        model_path, preproc_path, metadata_path = self.save_model_artifacts(
            final_model, scaler, X.columns.tolist(), evaluation_results, best_params
        )
        
        return {
            'model_path': model_path,
            'preproc_path': preproc_path,
            'metadata_path': metadata_path,
            'evaluation_results': evaluation_results
        }

if __name__ == "__main__":
    # Create sample data first if it doesn't exist
    data_path = Path("./data/features.parquet")
    
    if not data_path.exists():
        logger.info("Sample data not found, creating it first...")
        import sys
        sys.path.append('.')
        from download_dataset import DatasetDownloader
        
        downloader = DatasetDownloader()
        features_path, _ = downloader.create_sample_dataset()
        data_path = features_path
    
    # Train model
    trainer = APKModelTrainer(data_path)
    results = trainer.train_pipeline()
    
    print(f"\nTraining completed successfully!")
    print(f"Model: {results['model_path']}")
    print(f"Preprocessor: {results['preproc_path']}")
    print(f"Metadata: {results['metadata_path']}")
    print(f"AUC Score: {results['evaluation_results']['auc_score']:.3f}")
