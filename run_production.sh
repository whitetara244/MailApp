#!/bin/bash

# Production startup script (compatible version)

echo "Starting M365 Phisher with Gunicorn..."

# Create required directories
mkdir -p logs exploits templates

# Kill existing Gunicorn processes (alternative methods)
if command -v pkill &> /dev/null; then
    pkill -f "gunicorn.*wsgi" || true
elif command -v killall &> /dev/null; then
    killall gunicorn 2>/dev/null || true
else
    # Manual kill by PID
    PID_FILE="gunicorn.pid"
    if [ -f "$PID_FILE" ]; then
        kill -9 $(cat $PID_FILE) 2>/dev/null || true
        rm -f $PID_FILE
    fi
    # Kill any gunicorn processes
    ps aux | grep gunicorn | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null || true
fi

sleep 2

# Check if gunicorn is installed
if ! command -v gunicorn &> /dev/null; then
    echo "Gunicorn not found! Installing..."
    pip install gunicorn
fi

# Start Gunicorn with PID file
gunicorn -c gunicorn_config.py wsgi:application --pid gunicorn.pid