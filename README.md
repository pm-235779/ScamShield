# SCAMSHIELD - Fake Banking APK Detection

A modern cybersecurity web application that detects fake/malicious banking APKs using machine learning and static analysis.

## Features

- **ML-Powered Detection**: Uses trained models with Androguard static analysis
- **Risk Scoring**: 0-10 risk score with detailed explanations
- **Comparison Mode**: Side-by-side analysis of two APKs
- **Modern UI**: React + TailwindCSS with dark mode
- **Real-time Analysis**: FastAPI backend with instant results

## Tech Stack

- **Frontend**: React + Vite + TailwindCSS + Framer Motion
- **Backend**: FastAPI + Python
- **ML**: Scikit-learn + XGBoost + Androguard
- **Database**: SQLite
- **Deployment**: Docker + Docker Compose

## Quick Start

```bash
# Clone and setup
git clone <repo>
cd apkshield

# Run with Docker
docker-compose up --build

# Or run locally
pip install -r backend/requirements.txt
cd frontend && npm install
```

## Project Structure

```
apkshield/
├── backend/           # FastAPI backend
├── frontend/          # React frontend
├── ml/               # ML training pipeline
├── data/             # Datasets and models
├── docker-compose.yml
└── README.md
```

## Demo Flow

1. Upload official banking APK → **Safe** (low score)
2. Upload malicious APK → **High Risk** (high score)
3. Compare mode shows concrete differences
4. View analysis history and metrics
