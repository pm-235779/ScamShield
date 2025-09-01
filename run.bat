@echo off
REM APKShield Development Runner for Windows
REM Quick start script for local development

echo 🚀 Starting APKShield Development Environment
echo =============================================

REM Check if Docker is available
docker --version >nul 2>&1
if %errorlevel% == 0 (
    docker-compose --version >nul 2>&1
    if %errorlevel% == 0 (
        echo 🐳 Docker detected - Starting with Docker Compose...
        docker-compose up --build
        goto :end
    )
)

echo 📦 Docker not found - Starting locally...

REM Start backend
echo 🔧 Starting FastAPI backend...
start "APKShield Backend" cmd /k "cd backend && uvicorn main:app --reload --host 0.0.0.0 --port 8000"

REM Wait a moment for backend to start
timeout /t 3 /nobreak >nul

REM Start frontend
echo ⚛️ Starting React frontend...
start "APKShield Frontend" cmd /k "cd frontend && npm run dev"

echo ✅ Services started!
echo 📱 Frontend: http://localhost:3000
echo 🔧 Backend API: http://localhost:8000
echo 📚 API Docs: http://localhost:8000/docs

pause

:end
