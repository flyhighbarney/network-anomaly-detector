"""Convenience launcher for the Flask dashboard.

Runs the app regardless of the current working directory (Python puts this
script's directory on sys.path, so ``import src...`` resolves). Equivalent to
``python -m src.dashboard.app`` but reloader-free for stable previewing.
"""
from src.dashboard.app import app

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
