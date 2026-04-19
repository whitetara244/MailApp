import os
import sys
from app import app

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Create required directories
os.makedirs('logs', exist_ok=True)
os.makedirs('exploits', exist_ok=True)
os.makedirs('templates', exist_ok=True)

# Application instance
application = app

if __name__ == "__main__":
    app.run()