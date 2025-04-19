import os
import uvicorn
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get configuration from environment variables with defaults
port = int(os.getenv("PORT", 8000))
host = os.getenv("HOST", "0.0.0.0")
log_level = os.getenv("LOG_LEVEL", "info").lower()

if __name__ == "__main__":
    print(f"Starting GitHub AI Tool server on http://{host}:{port}")
    print(f"Visit http://localhost:{port}/docs for API documentation")
    uvicorn.run("app.main:app", host=host, port=port, log_level=log_level, reload=True)

