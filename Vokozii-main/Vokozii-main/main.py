"""
Evil Twin Detection System - Main Entry Point
Complete production-ready Windows-native security application
"""

import sys
import os
from pathlib import Path

# Add app directory to path
app_dir = Path(__file__).parent / "app"
sys.path.insert(0, str(app_dir.parent))

from app.database import SecurityDatabase
from app.ui import SecurityApp


def main():
    """
    Application entry point.
    Initializes database and starts the UI event loop.
    """
    # Initialize database with SQLite WAL mode
    db = SecurityDatabase("security.db")
    
    # Create and run the application
    app = SecurityApp(db)
    app.run()


if __name__ == "__main__":
    main()
