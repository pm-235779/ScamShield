#!/usr/bin/env python3
"""
APKShield Setup Script
Initializes the project, creates sample data, and trains the ML model
"""

import os
import sys
import subprocess
from pathlib import Path

def run_command(cmd, cwd=None):
    """Run a command and return success status"""
    try:
        result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"❌ Command failed: {cmd}")
            print(f"Error: {result.stderr}")
            return False
        return True
    except Exception as e:
        print(f"❌ Error running command: {e}")
        return False

def setup_directories():
    """Create necessary directories"""
    dirs = ['data', 'models', 'logs']
    for dir_name in dirs:
        Path(dir_name).mkdir(exist_ok=True)
        print(f"✅ Created directory: {dir_name}")

def install_python_dependencies():
    """Install Python dependencies"""
    print("📦 Installing Python dependencies...")
    if run_command("pip install -r backend/requirements.txt"):
        print("✅ Python dependencies installed")
        return True
    return False

def install_frontend_dependencies():
    """Install frontend dependencies"""
    print("📦 Installing frontend dependencies...")
    if run_command("npm install", cwd="frontend"):
        print("✅ Frontend dependencies installed")
        return True
    return False

def create_sample_data():
    """Create sample dataset for development"""
    print("📊 Creating sample dataset...")
    if run_command("python ml/dataset_downloader.py"):
        print("✅ Sample dataset created")
        return True
    return False

def extract_features():
    """Extract features from dataset"""
    print("🔍 Extracting features...")
    if run_command("python ml/extract_features.py"):
        print("✅ Features extracted")
        return True
    return False

def train_model():
    """Train the ML model"""
    print("🤖 Training ML model...")
    if run_command("python ml/train_model.py"):
        print("✅ Model trained successfully")
        return True
    return False

def main():
    """Main setup function"""
    print("🚀 Setting up APKShield...")
    print("=" * 50)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        sys.exit(1)
    
    # Setup directories
    setup_directories()
    
    # Install dependencies
    if not install_python_dependencies():
        print("❌ Failed to install Python dependencies")
        sys.exit(1)
    
    if not install_frontend_dependencies():
        print("❌ Failed to install frontend dependencies")
        sys.exit(1)
    
    # Create sample data and train model
    if not create_sample_data():
        print("❌ Failed to create sample data")
        sys.exit(1)
    
    if not extract_features():
        print("❌ Failed to extract features")
        sys.exit(1)
    
    if not train_model():
        print("❌ Failed to train model")
        sys.exit(1)
    
    print("\n🎉 APKShield setup completed successfully!")
    print("\n📋 Next steps:")
    print("1. Run with Docker: docker-compose up --build")
    print("2. Or run locally:")
    print("   - Backend: cd backend && uvicorn main:app --reload")
    print("   - Frontend: cd frontend && npm run dev")
    print("\n🌐 Access the application at: http://localhost:3000")

if __name__ == "__main__":
    main()
