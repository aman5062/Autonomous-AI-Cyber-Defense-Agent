"""Initialize the test application database."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from test_app.vulnerable_app import init_db

if __name__ == "__main__":
    init_db()
    print("Test database initialized.")
