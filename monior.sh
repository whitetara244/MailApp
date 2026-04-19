#!/bin/bash

# Check if Gunicorn is running
if pgrep -f "gunicorn.*wsgi" > /dev/null; then
    echo "✅ Gunicorn is running"
    echo "Processes: $(pgrep -f "gunicorn.*wsgi" | wc -l)"
    echo "Memory usage:"
    ps aux | grep gunicorn | grep -v grep | awk '{print $2, $4, $6, $11}'
else
    echo "❌ Gunicorn is not running"
    exit 1
fi

# Check database size
if [ -f logs.db ]; then
    echo "Database size: $(du -h logs.db | cut -f1)"
fi

# Check exploit directory
if [ -d exploits ]; then
    echo "Exploits directory: $(du -sh exploits | cut -f1)"
    echo "Victims: $(ls -1 exploits | wc -l)"
fi