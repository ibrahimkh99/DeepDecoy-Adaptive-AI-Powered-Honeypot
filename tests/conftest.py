import os
import sys

# Ensure project root is on sys.path so tests can import modules
PROJECT_ROOT = os.path.dirname(os.path.abspath(os.path.join(__file__, '..')))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
