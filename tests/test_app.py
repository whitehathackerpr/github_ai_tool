import os
import sys
import pytest
from fastapi.testclient import TestClient

# Add the parent directory to the path so we can import the app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.main import app

client = TestClient(app)

def test_root_endpoint():
    """Test that the root endpoint returns the expected message"""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Welcome to GitHub AI Tool API. Visit /docs for documentation."}

def test_health_endpoint():
    """Test that the health endpoint returns healthy status"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}

