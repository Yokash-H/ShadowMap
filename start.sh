#!/bin/bash
echo "Starting ShadowMap AI..."

# Start Backend
cd backend && python app.py &
BACKEND_PID=$!

sleep 2

# Start Dashboard
cd dashboard && npm start &
DASHBOARD_PID=$!

sleep 3

# Start Electron App
cd electron-app && npm start &
ELECTRON_PID=$!

# Trap cleanup
trap "kill $BACKEND_PID $DASHBOARD_PID $ELECTRON_PID; exit" INT TERM EXIT

wait
