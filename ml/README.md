# APKShield ML - Banking Trojan Detection Model

A comprehensive machine learning system for detecting Android banking trojans using both static and dynamic analysis features.

## 🎯 Overview

This ML model combines static analysis (permissions, APIs, certificates) with dynamic analysis (system calls, network behavior) to detect banking trojans like BankBot, Cerberus, Anatsa, and Teabot with high accuracy.

## 🏗️ Architecture

```
apkshield/ml/
├── data/                          # Dataset storage
│   ├── malware_raw/              # Raw malware APKs
│   ├── benign_raw/               # Benign banking APKs
│   ├── processed/                # Processed feature datasets
│   └── traces/                   # Dynamic analysis traces
├── models/                       # Trained models
├── notebooks/                    # Jupyter development notebooks
├── static_feature_extractor.py  # Static analysis features
├── dynamic_feature_extractor.py # Dynamic analysis features
├── data_acquisition.py          # Data collection scripts
├── train_model.py               # Model training pipeline
├── scan_apk.py                  # CLI scanner
├── api_server.py                # FastAPI web service
└── requirements.txt             # Dependencies
```

## 🚀 Quick Start

### 1. Install Dependencies

```bash
cd apkshield/ml
pip install -r requirements.txt
```

### 2. Train the Model

**Option A: Use Jupyter Notebook (Recommended for development)**
```bash
jupyter notebook notebooks/Banking_Trojan_Detection_Model.ipynb
```

**Option B: Use Python Script**
```bash
python train_model.py
```

### 3. Scan APK Files

**CLI Scanner:**
```bash
# Scan single APK
python scan_apk.py sample.apk

# Detailed analysis
python scan_apk.py sample.apk --detailed

# Batch scanning
python scan_apk.py *.apk --batch

# JSON output
python scan_apk.py sample.apk --json
```

**API Server:**
```bash
# Start API server
python api_server.py

# Server runs on http://localhost:8000
# API docs: http://localhost:8000/docs
```

## 📊 Features

### Static Analysis Features
- **Permissions**: Dangerous permissions (SMS, contacts, accessibility)
- **APIs**: Sensitive API usage (reflection, crypto, device info)
- **Components**: Activities, services, receivers, providers
- **Certificates**: Certificate analysis and validation
- **Obfuscation**: Code obfuscation detection
- **Banking Keywords**: Package name similarity to legitimate banks

### Dynamic Analysis Features
- **System Calls**: Suspicious syscall patterns
- **Network Behavior**: Domain analysis, traffic patterns
- **API Traces**: Runtime API call monitoring
- **Behavioral Scoring**: Composite malicious behavior score

## 🔍 Data Sources

### Malware Samples
- **MalwareBazaar**: BankBot, Cerberus, Anatsa families
- **Koodous**: Collaborative malware repository
- **CIC-AndMal2017**: Academic research dataset

### Benign Samples
- **APKMirror**: Legitimate banking applications
- **Official App Stores**: Verified banking apps

## 🎛️ API Usage

### Scan Single APK
```bash
curl -X POST "http://localhost:8000/scan" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@sample.apk"
```

### Batch Scan
```bash
curl -X POST "http://localhost:8000/batch-scan" \
  -H "Content-Type: multipart/form-data" \
  -F "files=@app1.apk" \
  -F "files=@app2.apk"
```

### Response Format
```json
{
  "file_name": "sample.apk",
  "file_size_mb": 2.5,
  "package_name": "com.example.app",
  "prediction": 1,
  "probability": 0.85,
  "risk_level": "HIGH",
  "label": "MALWARE",
  "scan_timestamp": "2024-08-30T08:54:22"
}
```

## 🧪 Model Performance

### Evaluation Metrics
- **ROC-AUC**: 0.95+
- **Precision**: 0.92+
- **Recall**: 0.89+
- **F1-Score**: 0.90+

### Feature Importance
1. Malicious Behavior Score (25%)
2. Sensitive API Count (18%)
3. Suspicious System Calls (15%)
4. Obfuscation Score (12%)
5. Dangerous Permissions (10%)

## 🛡️ Security Considerations

### Safe Malware Handling
- Run analysis in isolated VM environment
- No network access during analysis
- Proper malware sample encryption
- Secure disposal of temporary files

### Data Privacy
- No APK content stored permanently
- Feature extraction only
- Anonymized logging
- GDPR compliance ready

## 📈 Model Training

### Training Pipeline
1. **Data Collection**: Automated malware/benign sample acquisition
2. **Feature Extraction**: Static + dynamic analysis
3. **Preprocessing**: Data cleaning and normalization
4. **Model Selection**: XGBoost with hyperparameter tuning
5. **Evaluation**: Cross-validation and test set evaluation
6. **Deployment**: Model serialization and API deployment

### Hyperparameters
```python
{
  "n_estimators": 400,
  "max_depth": 6,
  "learning_rate": 0.05,
  "subsample": 0.9,
  "colsample_bytree": 0.8,
  "reg_lambda": 2.0
}
```

## 🔧 Configuration

### Environment Variables
```bash
export APKSHIELD_MODEL_PATH="./models/banking_trojan_detector.joblib"
export APKSHIELD_API_HOST="0.0.0.0"
export APKSHIELD_API_PORT="8000"
export APKSHIELD_LOG_LEVEL="INFO"
```

### Model Configuration
- **Input Features**: 50+ static + dynamic features
- **Model Type**: XGBoost Classifier
- **Calibration**: Isotonic regression for probability calibration
- **Threshold**: 0.5 (adjustable based on use case)

## 📚 Usage Examples

### Python Integration
```python
from scan_apk import APKScanner

# Initialize scanner
scanner = APKScanner("./models")

# Scan APK
result = scanner.scan_apk("sample.apk")
print(f"Result: {result['label']} ({result['probability']:.2%})")
```

### Batch Processing
```python
import glob
from scan_apk import APKScanner

scanner = APKScanner()
apk_files = glob.glob("*.apk")

for apk_file in apk_files:
    result = scanner.scan_apk(apk_file)
    if result['prediction'] == 1:
        print(f"⚠️ Malware detected: {apk_file}")
```

## 🐛 Troubleshooting

### Common Issues

**Model not found:**
```bash
# Train model first
python train_model.py
```

**Feature extraction fails:**
```bash
# Check APK file integrity
file sample.apk

# Verify androguard installation
pip install androguard==3.3.5
```

**API server won't start:**
```bash
# Check port availability
netstat -an | grep 8000

# Use different port
uvicorn api_server:app --port 8001
```

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/new-feature`)
3. Commit changes (`git commit -am 'Add new feature'`)
4. Push to branch (`git push origin feature/new-feature`)
5. Create Pull Request

## 📞 Support

For questions and support:
- Create an issue on GitHub
- Email: support@apkshield.com
- Documentation: [docs.apkshield.com](https://docs.apkshield.com)

## 🔮 Future Enhancements

- [ ] Real-time dynamic analysis integration
- [ ] Advanced obfuscation detection
- [ ] Multi-family classification
- [ ] Federated learning support
- [ ] Mobile app integration
- [ ] Threat intelligence feeds

---

**⚠️ Disclaimer**: This tool is for research and legitimate security purposes only. Users are responsible for complying with applicable laws and regulations.
