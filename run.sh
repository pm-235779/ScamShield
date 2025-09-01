#!/bin/bash

# APKShield Development Runner
# Quick start script for local development

echo "🚀 Starting APKShield Development Environment"
echo "============================================="

# Check if Docker is available
if command -v docker &> /dev/null && command -v docker-compose &> /dev/null; then
    echo "🐳 Docker detected - Starting with Docker Compose..."
    docker-compose up --build
else
    echo "📦 Docker not found - Starting locally..."
    
    # Start backend
    echo "🔧 Starting FastAPI backend..."
    cd backend
    uvicorn main:app --reload --host 0.0.0.0 --port 8000 &
    BACKEND_PID=$!
    cd ..
    
    # Start frontend
    echo "⚛️ Starting React frontend..."
    cd frontend
    npm run dev &
    FRONTEND_PID=$!
    cd ..
    
    echo "✅ Services started!"
    echo "📱 Frontend: http://localhost:3000"
    echo "🔧 Backend API: http://localhost:8000"
    echo "📚 API Docs: http://localhost:8000/docs"
    
    # Wait for interrupt
    trap "echo 'Stopping services...'; kill $BACKEND_PID $FRONTEND_PID; exit" INT
    wait
fi
