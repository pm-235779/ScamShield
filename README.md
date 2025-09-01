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


![WhatsApp Image 2025-09-01 at 20 51 49_51509b63](https://github.com/user-attachments/assets/6564523f-1014-475f-8eec-91148bc39f00)
![WhatsApp Image 2025-09-01 at 20 51 49_44ee2b37](https://github.com/user-attachments/assets/38edf87e-413d-4942-b90f-f39cdc5f4609)
![WhatsApp Image 2025-09-01 at 20 51 49_51be6173](https://github.com/user-attachments/assets/cbbbbe8f-76be-4300-80e2-d84f5255f932)
![WhatsApp Image 2025-09-01 at 20 51 49_b1675ce5](https://github.com/user-attachments/assets/581feb34-6ea4-42e6-a436-b9b3bf6443be)
![WhatsApp Image 2025-09-01 at 20 51 49_cc45fbb5](https://github.com/user-attachments/assets/541f1c38-58b5-4e78-a964-c1d3467b2c42)
![WhatsApp Image 2025-09-01 at 20 51 49_b87d9e25](https://github.com/user-attachments/assets/36b84cec-c0c7-47e3-ab70-78df01bfaeeb)
![WhatsApp Image 2025-09-01 at 20 51 50_0c3dc78a](https://github.com/user-attachments/assets/d1575f8d-1b23-4d8d-8adb-230d89ec47e4)
![WhatsApp Image 2025-09-01 at 20 51 50_695395c4](https://github.com/user-attachments/assets/599abfd7-bd57-474a-8d1e-9d8524f8b591)

DEMO VIDEO ->

https://drive.google.com/file/d/1IW66ammPw3J1LNed9WY3iwV6T1wEZqml/view?usp=sharing








