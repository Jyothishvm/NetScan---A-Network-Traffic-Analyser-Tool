import uvicorn
import multiprocessing
import os
import sys
from main import app

# Add the current directory to path if running compiled
if getattr(sys, 'frozen', False):
    os.environ["PATH"] += os.pathsep + os.path.dirname(sys.executable)

if __name__ == "__main__":
    # Required for Windows executables using multiprocessing (which Uvicorn uses inside)
    multiprocessing.freeze_support()
    
    # Run the FastAPI app directly (no string references for PyInstaller)
    # Using 127.0.0.1 to avoid Windows Firewall prompts for external access
    uvicorn.run(app, host="127.0.0.1", port=8000)
