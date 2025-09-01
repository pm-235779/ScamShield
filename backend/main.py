from fastapi import FastAPI, File, UploadFile, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import os
import hashlib
import tempfile
import json
from typing import List, Optional
import joblib
import pandas as pd
from datetime import datetime
import sqlite3
from pathlib import Path

from models.database import init_db, log_analysis, get_analysis_history
from services.apk_analyzer import APKAnalyzer
from services.ml_predictor import MLPredictor
from services.model_trainer import ensure_models_exist
from schemas.responses import AnalysisResponse, ComparisonResponse, HistoryResponse
from utils.warning_suppressor import suppress_all_ml_warnings

app = FastAPI(title="APKShield API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances
apk_analyzer = APKAnalyzer()
ml_predictor = None

@app.on_event("startup")
async def startup_event():
    """Initialize database and load ML model on startup"""
    global ml_predictor
    
    # Suppress all ML-related warnings
    suppress_all_ml_warnings()
    
    # Initialize database
    init_db()
    
    # Ensure models directory exists and create models if needed
    models_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')
    os.makedirs(models_dir, exist_ok=True)
    
    # Try to ensure models exist (create if missing)
    ensure_models_exist(models_dir)
    
    # Load ML model - check multiple possible paths
    model_paths = [
        os.path.join(models_dir, 'apkshield_model.joblib'),
        os.getenv("MODEL_PATH", "../models/apkshield_model.joblib"),
        "../models/banking_trojan_detector.joblib",
        "./models/apkshield_model.joblib",
        "./models/banking_trojan_detector.joblib"
    ]
    
    preproc_paths = [
        os.path.join(models_dir, 'preproc.joblib'),
        os.getenv("PREPROC_PATH", "../models/preproc.joblib"),
        "../models/preproc.joblib",
        "./models/preproc.joblib"
    ]
    
    model_path = None
    preproc_path = None
    
    # Find existing model file
    for path in model_paths:
        if os.path.exists(path):
            model_path = path
            break
    
    # Find existing preprocessor file
    for path in preproc_paths:
        if os.path.exists(path):
            preproc_path = path
            break
    
    # Initialize ML predictor (will use enhanced rule-based if no models)
    try:
        ml_predictor = MLPredictor(model_path, preproc_path)
        if model_path and preproc_path:
            print(f"✅ ML model loaded from {model_path}")
        else:
            print(f"✅ Enhanced rule-based analysis initialized")
    except Exception as e:
        print(f"⚠️ Could not initialize predictor: {e}")
        ml_predictor = MLPredictor()  # Fallback to rule-based only

@app.get("/")
async def root():
    return {"message": "APKShield API is running", "status": "healthy"}

@app.post("/analyze_apk", response_model=AnalysisResponse)
async def analyze_apk(file: UploadFile = File(...)):
    """Analyze an APK file for malicious behavior"""
    
    if not file.filename.endswith('.apk'):
        raise HTTPException(status_code=400, detail="Only APK files are allowed")
    
    # Create temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as tmp_file:
        content = await file.read()
        tmp_file.write(content)
        tmp_path = tmp_file.name
    
    try:
        # Calculate file hash
        file_hash = hashlib.sha256(content).hexdigest()
        print(f"Analyzing APK: {file.filename}, Hash: {file_hash[:8]}...")
        
        # Analyze APK with Androguard
        apk_info = apk_analyzer.analyze(tmp_path)
        print(f"APK Info extracted: {apk_info['package_name']}")
        
        # Extract features for ML
        features = apk_analyzer.extract_features(apk_info)
        print(f"Features extracted: {len(features)} features")
        print(f"Key features: dangerous_permissions={features.get('dangerous_permissions', 0)}, total_permissions={features.get('total_permissions', 0)}, is_self_signed={features.get('is_self_signed', 0)}")
        print(f"All extracted features: {list(features.keys())}")
        
        # Predict with ML model with NaN protection
        risk_score = 5.0  # Default fallback
        verdict = "Unknown"
        top_features = []
        confidence = 0.5
        probabilities = {'safe': 0.5, 'malicious': 0.5}
        
        if ml_predictor:
            try:
                print("Running ML prediction...")
                prediction = ml_predictor.predict(features)
                
                # Extract prediction results with NaN protection
                import math
                
                risk_score = prediction.get('risk_score', 5.0)
                if math.isnan(risk_score) or math.isinf(risk_score):
                    risk_score = 5.0
                
                confidence = prediction.get('confidence', 0.5)
                if math.isnan(confidence) or math.isinf(confidence):
                    confidence = 0.5
                
                # Get probabilities safely
                pred_probs = prediction.get('probabilities', {'safe': 0.5, 'malicious': 0.5})
                safe_prob = pred_probs.get('safe', 0.5)
                malicious_prob = pred_probs.get('malicious', 0.5)
                
                # NaN protection for probabilities
                if math.isnan(safe_prob) or math.isinf(safe_prob):
                    safe_prob = 0.5
                if math.isnan(malicious_prob) or math.isinf(malicious_prob):
                    malicious_prob = 0.5
                
                probabilities = {
                    'safe': float(safe_prob),
                    'malicious': float(malicious_prob)
                }
                
                verdict = prediction.get('verdict', 'Unknown')
                top_features = prediction.get('feature_importance', prediction.get('top_features', []))
                
                print(f"ML prediction successful: {verdict} ({risk_score:.2f})")
                print(f"Confidence: {confidence:.3f}, Probabilities: Safe={safe_prob:.3f}, Malicious={malicious_prob:.3f}")
                print(f"Top features returned: {len(top_features)} features")
                
            except Exception as e:
                print(f"ML prediction error: {e}")
                import traceback
                traceback.print_exc()
        else:
            print("No ML model available, using rule-based analysis only")
            # Create fallback features when no ML model
            from services.ml_predictor import MLPredictor
            temp_predictor = MLPredictor.__new__(MLPredictor)
            top_features = temp_predictor._create_rule_based_importance(features)
        
        # Ensure we have feature explanations even if ML model fails
        if not top_features:
            print("No top features found, creating rule-based explanations...")
            from services.ml_predictor import MLPredictor
            temp_predictor = MLPredictor.__new__(MLPredictor)
            top_features = temp_predictor._create_rule_based_importance(features)
            print(f"Created {len(top_features)} rule-based features")
        
        # Apply rule-based adjustments
        risk_score = apply_rule_adjustments(risk_score, apk_info)
        verdict = get_verdict_from_score(risk_score)
        print(f"Final verdict: {verdict} ({risk_score})")
        print(f"Final top_features count: {len(top_features)}")
        
        # Build response with comprehensive data and NaN protection
        import math
        import time
        
        start_time = time.time()
        
        # Ensure all numeric values are safe
        safe_risk_score = float(risk_score) if not (math.isnan(risk_score) or math.isinf(risk_score)) else 5.0
        safe_confidence = float(confidence) if not (math.isnan(confidence) or math.isinf(confidence)) else 0.5
        
        response_data = {
            "verdict": verdict,
            "risk_score": safe_risk_score,
            "confidence": safe_confidence,
            "probabilities": probabilities,
            "analysis_time": time.time() - start_time,
            "file_hash": file_hash,
            "package_name": apk_info.get('package_name', 'Unknown'),
            "app_name": apk_info.get('app_name', 'Unknown'),
            "version_name": apk_info.get('version_name', 'Unknown'),
            "version_code": apk_info.get('version_code', 0),
            "min_sdk": apk_info.get('min_sdk', 0),
            "target_sdk": apk_info.get('target_sdk', 0),
            "file_size_human": f"{len(content) / (1024*1024):.1f} MB",
            "permissions": apk_info.get('permissions', []),
            "dangerous_permissions": apk_info.get('dangerous_permissions', []),
            "activities": apk_info.get('activities', []),
            "services": apk_info.get('services', []),
            "receivers": apk_info.get('receivers', []),
            "certificate_info": apk_info.get('certificate_info', {}),
            "top_features": top_features,
            "allows_backup": apk_info.get('allows_backup', True),
            "is_debuggable": apk_info.get('is_debuggable', False),
            "install_location": apk_info.get('install_location', 'auto'),
            "component_summary": {
                "activities": len(apk_info.get('activities', [])),
                "services": len(apk_info.get('services', [])),
                "receivers": len(apk_info.get('receivers', []))
            }
        }
        
        response = AnalysisResponse(
            app_name=apk_info.get('app_name', 'Unknown'),
            package_name=apk_info.get('package_name', 'Unknown'),
            version_name=apk_info.get('version_name', 'Unknown'),
            version_code=apk_info.get('version_code', 0),
            min_sdk=apk_info.get('min_sdk', 0),
            target_sdk=apk_info.get('target_sdk', 0),
            permissions=apk_info.get('permissions', []),
            dangerous_permissions=apk_info.get('dangerous_permissions', []),
            risk_score=round(safe_risk_score, 1),
            verdict=verdict,
            top_features=top_features,
            certificate_info=apk_info.get('certificate_info', {}),
            suspicious_strings=apk_info.get('suspicious_strings', [])[:10],
            file_size_human=f"{len(content) / (1024*1024):.1f} MB",
            install_location=apk_info.get('install_location', 'auto'),
            allows_backup=apk_info.get('allows_backup', True),
            is_debuggable=apk_info.get('is_debuggable', False),
            component_summary={
                "activities": len(apk_info.get('activities', [])),
                "services": len(apk_info.get('services', [])),
                "receivers": len(apk_info.get('receivers', []))
            },
            activities=apk_info.get('activities', []),
            services=apk_info.get('services', [])
        )
        
        return response
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    
    finally:
        # Clean up temporary file
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

@app.get("/history", response_model=List[HistoryResponse])
async def get_history(limit: int = 50, offset: int = 0):
    """Get analysis history"""
    try:
        history = get_analysis_history(limit, offset)
        return history
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get history: {str(e)}")

@app.post("/compare", response_model=ComparisonResponse)
async def compare_apks(
    file1: UploadFile = File(...),
    file2: UploadFile = File(...)
):
    """Compare two APK files side by side"""
    
    print(f"Starting comparison: {file1.filename} vs {file2.filename}")
    
    if not (file1.filename.endswith('.apk') and file2.filename.endswith('.apk')):
        raise HTTPException(status_code=400, detail="Both files must be APK files")
    
    # Analyze both APKs
    results = []
    temp_files = []
    
    try:
        for i, file in enumerate([file1, file2], 1):
            print(f"Processing APK {i}: {file.filename}")
            
            with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as tmp_file:
                content = await file.read()
                print(f"Read {len(content)} bytes from {file.filename}")
                tmp_file.write(content)
                temp_files.append(tmp_file.name)
                
                try:
                    # Analyze APK
                    print(f"Analyzing APK {i}...")
                    apk_info = apk_analyzer.analyze(tmp_file.name)
                    print(f"APK {i} analysis complete: {apk_info.get('app_name', 'Unknown')}")
                    
                    features = apk_analyzer.extract_features(apk_info)
                    print(f"Features extracted for APK {i}")
                    
                    # Get ML prediction
                    risk_score = 5.0
                    verdict = "Unknown"
                    
                    if ml_predictor:
                        try:
                            prediction = ml_predictor.predict(features)
                            risk_score = prediction['risk_score']
                            verdict = prediction['verdict']
                            print(f"ML prediction for APK {i}: {risk_score}")
                        except Exception as e:
                            print(f"ML prediction error for APK {i}: {e}")
                    
                    risk_score = apply_rule_adjustments(risk_score, apk_info)
                    verdict = get_verdict_from_score(risk_score)
                    print(f"Final risk score for APK {i}: {risk_score}")
                    
                    results.append({
                        'filename': file.filename,
                        'app_name': apk_info['app_name'],
                        'package_name': apk_info['package_name'],
                        'version_name': apk_info['version_name'],
                        'version_code': apk_info.get('version_code', 0),
                        'min_sdk': apk_info.get('min_sdk', 0),
                        'target_sdk': apk_info.get('target_sdk', 0),
                        'permissions': apk_info['permissions'],
                        'dangerous_permissions': apk_info.get('dangerous_permissions', []),
                        'risk_score': round(risk_score, 1),
                        'verdict': verdict,
                        'certificate_info': apk_info['certificate_info'],
                        'file_size_human': apk_info.get('file_size_human', 'Unknown'),
                        'component_summary': apk_info.get('component_summary', {}),
                        'suspicious_strings': apk_info.get('suspicious_strings', [])[:5]
                    })
                    
                except Exception as e:
                    print(f"Error analyzing APK {i}: {str(e)}")
                    raise HTTPException(status_code=500, detail=f"Failed to analyze {file.filename}: {str(e)}")
        
        print("Calculating comparison metrics...")
        
        # Calculate comprehensive differences
        perm_diff_1_to_2 = set(results[1]['permissions']) - set(results[0]['permissions'])
        perm_diff_2_to_1 = set(results[0]['permissions']) - set(results[1]['permissions'])
        dangerous_diff = set(results[1]['dangerous_permissions']) - set(results[0]['dangerous_permissions'])
        risk_diff = results[1]['risk_score'] - results[0]['risk_score']
        
        # Calculate similarity metrics
        common_perms = set(results[0]['permissions']) & set(results[1]['permissions'])
        total_unique_perms = set(results[0]['permissions']) | set(results[1]['permissions'])
        similarity_score = len(common_perms) / len(total_unique_perms) if total_unique_perms else 0
        
        print(f"Comparison complete. Risk difference: {risk_diff}, Similarity: {similarity_score}")
        
        return ComparisonResponse(
            apk1=results[0],
            apk2=results[1],
            permission_differences=list(perm_diff_1_to_2),
            permissions_only_in_apk1=list(perm_diff_2_to_1),
            dangerous_permission_differences=list(dangerous_diff),
            risk_score_difference=round(risk_diff, 1),
            similarity_score=round(similarity_score, 3),
            version_comparison={
                'apk1_newer': results[0]['version_code'] > results[1]['version_code'],
                'version_diff': results[0]['version_code'] - results[1]['version_code']
            },
            sdk_comparison={
                'target_sdk_diff': results[0]['target_sdk'] - results[1]['target_sdk'],
                'min_sdk_diff': results[0]['min_sdk'] - results[1]['min_sdk']
            }
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Comparison failed: {str(e)}")
    
    finally:
        # Clean up temporary files
        for tmp_path in temp_files:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

def apply_rule_adjustments(base_score: float, apk_info: dict) -> float:
    """Apply rule-based adjustments to ML score"""
    rule_weights = json.loads(os.getenv("RULE_WEIGHTS_JSON", "{}"))
    
    adjusted_score = base_score
    permissions = apk_info.get('permissions', [])
    
    # Check for dangerous permission combinations
    if 'SYSTEM_ALERT_WINDOW' in permissions and 'BIND_ACCESSIBILITY_SERVICE' in permissions:
        adjusted_score += rule_weights.get('system_alert', 1.5)
    
    # Check for suspicious URLs/IPs
    if apk_info.get('suspicious_strings'):
        adjusted_score += rule_weights.get('suspicious_url', 2.0)
    
    # Check certificate validity
    cert_info = apk_info.get('certificate_info', {})
    if cert_info.get('is_self_signed') or not cert_info.get('is_valid'):
        adjusted_score += rule_weights.get('invalid_cert', 2.0)
    
    return min(10.0, max(0.0, adjusted_score))

def get_verdict_from_score(score: float) -> str:
    """Convert risk score to verdict"""
    if score < 3.0:
        return "Safe"
    elif score < 7.0:
        return "Suspicious"
    else:
        return "High Risk"
