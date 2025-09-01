"""
FastAPI Server for Banking Trojan Detection
RESTful API service for scanning APK files using the trained ML model.
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import joblib
import pandas as pd
import tempfile
import os
import json
from pathlib import Path
from typing import Dict, List, Optional
import uvicorn
from pydantic import BaseModel
import hashlib
from datetime import datetime
import logging

from static_feature_extractor import extract_static_features
from dynamic_feature_extractor import create_mock_dynamic_features

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="APKShield Banking Trojan Detection API",
    description="ML-powered API for detecting Android banking trojans",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables for model
model = None
feature_names = None
model_metadata = None

class ScanResult(BaseModel):
    """Response model for scan results."""
    file_name: str
    file_size_mb: float
    package_name: str
    prediction: int
    probability: float
    risk_level: str
    label: str
    scan_timestamp: str
    features: Optional[Dict] = None

class BatchScanResult(BaseModel):
    """Response model for batch scan results."""
    total_files: int
    malware_detected: int
    benign_files: int
    results: List[ScanResult]

class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    model_loaded: bool
    model_version: Optional[str] = None
    uptime: str

def load_model():
    """Load the trained model and metadata."""
    global model, feature_names, model_metadata
    
    model_dir = Path("./models")
    
    try:
        # Load model
        model_path = model_dir / "banking_trojan_detector.joblib"
        if not model_path.exists():
            model_path = model_dir / "apkshield_model.joblib"
        
        if model_path.exists():
            model = joblib.load(model_path)
            logger.info(f"Model loaded from: {model_path}")
        else:
            raise FileNotFoundError("No trained model found")
        
        # Load feature names
        feature_names_path = model_dir / "feature_names.csv"
        if feature_names_path.exists():
            feature_names = pd.read_csv(feature_names_path)['feature'].tolist()
        else:
            # Default feature names
            feature_names = [
                'total_permissions', 'sensitive_api_count', 'obfuscation_score',
                'exported_components', 'has_native_code', 'pkg_has_bank_keyword',
                'sensitive_api_runtime', 'suspicious_syscalls', 'suspicious_domain_hits',
                'malicious_behavior_score'
            ]
        
        # Load metadata
        metadata_path = model_dir / "model_metadata.json"
        if metadata_path.exists():
            with open(metadata_path, 'r') as f:
                model_metadata = json.load(f)
        
        logger.info("Model and metadata loaded successfully")
        
    except Exception as e:
        logger.error(f"Error loading model: {e}")
        raise

def extract_apk_features(apk_path: str) -> Optional[Dict]:
    """Extract features from an APK file."""
    try:
        # Extract static features
        static_features = extract_static_features(apk_path)
        if not static_features:
            return None
        
        # Create mock dynamic features
        dynamic_features = create_mock_dynamic_features(static_features['sha256'])
        
        # Combine features
        combined_features = {**static_features, **dynamic_features}
        return combined_features
        
    except Exception as e:
        logger.error(f"Error extracting features: {e}")
        return None

def predict_malware(features: Dict) -> Dict:
    """Make prediction on extracted features."""
    try:
        # Create DataFrame with required features
        feature_dict = {name: features.get(name, 0) for name in feature_names}
        df = pd.DataFrame([feature_dict])
        
        # Make prediction
        prediction = model.predict(df)[0]
        probability = model.predict_proba(df)[0, 1]
        
        # Determine risk level
        if probability >= 0.8:
            risk_level = "HIGH"
        elif probability >= 0.5:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return {
            'prediction': int(prediction),
            'probability': float(probability),
            'risk_level': risk_level,
            'label': "MALWARE" if prediction == 1 else "BENIGN"
        }
        
    except Exception as e:
        logger.error(f"Error making prediction: {e}")
        return None
# 
# @app.on_event("startup")
async def startup_event():
    """Load model on startup."""
    load_model()

@app.get("/", response_model=Dict)
async def root():
    """Root endpoint with API information."""
    return {
        "message": "APKShield Banking Trojan Detection API",
        "version": "1.0.0",
        "endpoints": {
            "health": "/health",
            "scan": "/scan",
            "batch_scan": "/batch-scan",
            "docs": "/docs"
        }
    }

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy" if model is not None else "unhealthy",
        model_loaded=model is not None,
        model_version=model_metadata.get('model_version') if model_metadata else None,
        uptime=str(datetime.now())
    )

@app.post("/scan", response_model=ScanResult)
async def scan_apk(
    file: UploadFile = File(...),
    include_features: bool = False
):
    """Scan a single APK file for malware."""
    
    if not model:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    if not file.filename.lower().endswith('.apk'):
        raise HTTPException(status_code=400, detail="File must be an APK")
    
    # Create temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as tmp_file:
        content = await file.read()
        tmp_file.write(content)
        tmp_file_path = tmp_file.name
    
    try:
        # Extract features
        features = extract_apk_features(tmp_file_path)
        if not features:
            raise HTTPException(status_code=400, detail="Failed to extract features from APK")
        
        # Make prediction
        prediction_result = predict_malware(features)
        if not prediction_result:
            raise HTTPException(status_code=500, detail="Failed to make prediction")
        
        # Prepare response
        result = ScanResult(
            file_name=file.filename,
            file_size_mb=round(len(content) / (1024*1024), 2),
            package_name=features.get('package_name', 'Unknown'),
            prediction=prediction_result['prediction'],
            probability=prediction_result['probability'],
            risk_level=prediction_result['risk_level'],
            label=prediction_result['label'],
            scan_timestamp=datetime.now().isoformat(),
            features=features if include_features else None
        )
        
        logger.info(f"Scanned {file.filename}: {result.label} ({result.probability:.3f})")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error scanning APK: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
    finally:
        # Clean up temporary file
        if os.path.exists(tmp_file_path):
            os.unlink(tmp_file_path)

@app.post("/batch-scan", response_model=BatchScanResult)
async def batch_scan_apks(
    files: List[UploadFile] = File(...),
    include_features: bool = False
):
    """Scan multiple APK files for malware."""
    
    if not model:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    if len(files) > 10:  # Limit batch size
        raise HTTPException(status_code=400, detail="Maximum 10 files per batch")
    
    results = []
    malware_count = 0
    
    for file in files:
        if not file.filename.lower().endswith('.apk'):
            continue
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_file_path = tmp_file.name
        
        try:
            # Extract features
            features = extract_apk_features(tmp_file_path)
            if not features:
                continue
            
            # Make prediction
            prediction_result = predict_malware(features)
            if not prediction_result:
                continue
            
            # Create result
            result = ScanResult(
                file_name=file.filename,
                file_size_mb=round(len(content) / (1024*1024), 2),
                package_name=features.get('package_name', 'Unknown'),
                prediction=prediction_result['prediction'],
                probability=prediction_result['probability'],
                risk_level=prediction_result['risk_level'],
                label=prediction_result['label'],
                scan_timestamp=datetime.now().isoformat(),
                features=features if include_features else None
            )
            
            results.append(result)
            if result.prediction == 1:
                malware_count += 1
                
        except Exception as e:
            logger.error(f"Error scanning {file.filename}: {e}")
            continue
        finally:
            # Clean up temporary file
            if os.path.exists(tmp_file_path):
                os.unlink(tmp_file_path)
    
    return BatchScanResult(
        total_files=len(results),
        malware_detected=malware_count,
        benign_files=len(results) - malware_count,
        results=results
    )

@app.get("/model-info")
async def get_model_info():
    """Get information about the loaded model."""
    if not model:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    info = {
        "model_type": type(model).__name__,
        "feature_count": len(feature_names),
        "feature_names": feature_names
    }
    
    if model_metadata:
        info.update(model_metadata)
    
    return info

@app.get("/stats")
async def get_stats():
    """Get API usage statistics (placeholder)."""
    # In production, implement proper statistics tracking
    return {
        "total_scans": "N/A",
        "malware_detected": "N/A",
        "uptime": str(datetime.now()),
        "model_loaded": model is not None
    }

if __name__ == "__main__":
    # Run the server
    uvicorn.run(
        "api_server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
